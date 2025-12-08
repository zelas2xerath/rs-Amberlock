use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetKind {
    File,
    Directory,
    VolumeRoot,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtectMode {
    ReadOnly,
    Seal,
} // 温和/封印

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LabelLevel {
    Medium,
    High,
    System,
}

bitflags! {
    /// 强制策略位
    ////
    /// # 策略说明
    /// - NW (No-Write-Up): 禁止低完整性主体写入高完整性对象（**默认且可靠**）
    /// - NR (No-Read-Up): 禁止低完整性主体读取高完整性对象（**对文件不保证**）
    /// - NX (No-Execute-Up): 禁止低完整性主体执行高完整性代码（**对文件不保证**）
  #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
  pub struct MandPolicy: u32 {
    const NW = 0x1; // No-Write-Up
    const NR = 0x2; // No-Read-Up (对文件不保证，默认不用)
    const NX = 0x4; // No-Execute-Up (对文件不保证，默认不用)
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRecord {
    pub id: String,
    pub path: String,
    pub kind: TargetKind,
    pub mode: ProtectMode,
    pub level_applied: LabelLevel,
    pub policy: MandPolicy,
    pub time_utc: String,
    pub user_sid: String,
    pub owner_before: Option<String>,
    pub sddl_before: Option<String>,
    pub sddl_after: Option<String>,
    pub status: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub parallelism: usize,
    pub default_mode: ProtectMode,
    pub default_level: LabelLevel,
    pub enable_nr_nx: bool,
    pub log_path: String,
    pub vault_path: String,
    pub shell_integration: bool,
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub caller_il: LabelLevel,
    pub can_touch_sacl: bool,
    pub can_set_system: bool, // 具备 SeRelabelPrivilege
}

#[derive(Error, Debug)]
pub enum AmberlockError {
    #[error("Auth failed")]
    AuthFailed,
    #[error("Storage error: {0}")]
    Storage(#[from] anyhow::Error),
    #[error("Operation cancelled")]
    Cancelled,
    #[error("Win32 error {code}: {msg}")]
    Win32 { code: u32, msg: String },
    #[error("Privilege not held: {0}")]
    PrivilegeMissing(&'static str),
    #[error("Unsupported platform/operation")]
    Unsupported,
    #[error("Invalid label or SDDL")]
    InvalidLabel,
}
pub type Result<T> = std::result::Result<T, AmberlockError>;

#[derive(Debug)]
pub enum AppError {
    LockPoisoned,
    Io(std::io::Error),
    // ...
}

impl From<std::sync::PoisonError<std::sync::RwLockReadGuard<'_, Settings>>> for AppError {
    fn from(_: std::sync::PoisonError<std::sync::RwLockReadGuard<'_, Settings>>) -> Self {
        AppError::LockPoisoned
    }
}
