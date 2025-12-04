use super::error::Result;
use crate::setlabel::LabelLevel;

#[derive(Debug, Clone)]
pub struct CapabilityProbe {
    pub caller_il: LabelLevel,
    pub has_se_security: bool,
    pub has_se_relabel: bool,
    pub user_sid: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Privilege {
    SeSecurity,
    SeRelabel,
}

pub fn enable_privilege(p: Privilege, enable: bool) -> Result<bool>;

/// 读取当前进程令牌的完整性级别（Medium/High/System 映射）
pub fn read_process_il() -> Result<LabelLevel>;

/// 读取当前进程用户 SID（用于日志）
pub fn read_user_sid() -> Result<String>;

/// 启动前自检（IL + 特权）
pub fn probe_capability() -> Result<CapabilityProbe>;
