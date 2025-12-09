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

/// 能力探测报告
#[derive(Debug, Clone)]
pub struct CapabilityProbe {
    /// 调用者的完整性级别
    pub caller_il: LabelLevel,
    /// 是否拥有 SeSecurityPrivilege（访问 SACL）
    pub has_se_security: bool,
    /// 是否拥有 SeRelabelPrivilege（设置 System 级）
    pub has_se_relabel: bool,
    /// 用户 SID 字符串
    pub user_sid: String,
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
    #[error("Windows API error: {0}")]
    Win32Error(#[from] windows::core::Error),
}
pub type Result<T> = std::result::Result<T, AmberlockError>;
