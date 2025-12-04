use super::error::Result;
use crate::setlabel::{LabelLevel, MandPolicy};

/// 将 LabelLevel 映射到 SDDL 标记（"ME"/"HI"/"SI"）
pub fn level_to_sddl_token(level: LabelLevel) -> &'static str;

/// 构造 Mandatory Label 的 SDDL 段，如 "S:(ML;;NW;;;HI)"
pub fn build_ml_sddl(level: LabelLevel, policy: MandPolicy) -> String;

/// 从对象读取 SACL 中的 Mandatory Label（返回 level、policy、原始 SDDL）
pub fn read_ml_from_object(path: &str) -> Result<(Option<LabelLevel>, Option<MandPolicy>, String)>;

/// 清除对象中的 Mandatory Label（仅移除 ML ACE，不改 DACL/OWNER）
pub fn clear_ml_on_object(path: &str) -> Result<()>;
