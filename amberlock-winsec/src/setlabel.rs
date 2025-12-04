use super::error::Result;
use bitflags::bitflags;

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
