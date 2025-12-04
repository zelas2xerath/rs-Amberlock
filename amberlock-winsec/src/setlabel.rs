//! Mandatory Label 设置与移除
//!
//! 本模块是 winsec 的核心，实现：
//! - 设置对象的强制完整性标签
//! - 移除对象的标签
//! - 读取对象当前标签
//! - 自动降级逻辑（System → High）

use super::error::{Result, WinSecError};
use super::sddl::{build_ml_sddl, clear_ml_on_object, read_ml_from_object};
use super::token::{enable_privilege, Privilege};
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use windows::core::PWSTR;
use windows::Win32::{
    Foundation::{
        LocalFree,
        HLOCAL,
    },
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW
        ,
        SetNamedSecurityInfoW,
        SE_FILE_OBJECT,
    },
    Security::{
        LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SACL_SECURITY_INFORMATION,
    },
    System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelLevel {
    Medium,
    High,
    System,
}

bitflags! {
  #[derive(Clone, Debug)]pub struct MandPolicy: u32 { const NW = 0x1; const NR = 0x2; const NX = 0x4; }
}

#[derive(Debug, Clone)]
pub struct SddlLabel {
    pub sddl: String,
    pub level: LabelLevel,
    pub policy: MandPolicy,
}

pub fn compute_effective_level(desired: LabelLevel, can_set_system: bool) -> LabelLevel;

/// 获取对象当前 ML（若无则 level/policy 为 None），返回完整 SDDL 文本
pub fn get_object_label(path: &str) -> Result<SddlLabel>;

/// 设置对象 ML（常用：仅 NW；NR/NX 仅作为尝试位传入）
pub fn set_mandatory_label(path: &str, level: LabelLevel, policy: MandPolicy) -> Result<()>;

/// 移除对象 ML
pub fn remove_mandatory_label(path: &str) -> Result<()>;
