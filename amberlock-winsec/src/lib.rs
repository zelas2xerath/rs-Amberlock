#![cfg(target_os = "windows")]
pub mod impersonate;
mod sddl;
mod setlabel;
pub mod token;
mod treeops;

pub use impersonate::spawn_system_process;
pub use setlabel::{
    SddlLabel, compute_effective_level, get_object_label, level_to_sddl_token,
    remove_mandatory_label, set_mandatory_label,
};
pub use token::{Privilege, enable_privilege, read_process_il, read_user_sid};
pub use treeops::{TreeOptions, TreeStats, tree_apply_label, tree_remove_label};
