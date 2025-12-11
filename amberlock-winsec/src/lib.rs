#![cfg(target_os = "windows")]
pub mod impersonate;
mod sddl;
mod setlabel;
pub mod token;

pub use impersonate::spawn_system_process;
pub use setlabel::{
    SddlLabel, compute_effective_level, get_object_label, level_to_sddl_token,
    remove_mandatory_label, set_mandatory_label,
};
pub use token::{enable_privilege, read_process_il, read_user_sid};


/// 特权类型枚举
#[derive(Debug, Clone, Copy)]
pub enum Privilege {
    /// SE_SECURITY_NAME - 访问/修改 SACL 所需
    SeSecurity,
    /// SE_RELABEL_PRIVILEGE - 提升标签级别所需
    SeRelabel,
}

impl Privilege {
    /// 获取特权的系统名称
    fn name(&self) -> &'static str {
        match self {
            Privilege::SeSecurity => "SeSecurityPrivilege",
            Privilege::SeRelabel => "SeRelabelPrivilege",
        }
    }
}