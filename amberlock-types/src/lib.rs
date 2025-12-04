use bitflags::bitflags;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LabelLevel {
    Medium,
    High,
    System,
}

bitflags! {
  #[derive(Serialize, Deserialize, Clone, Debug)]
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
