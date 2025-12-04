use super::error::Result;
use crate::setlabel::{LabelLevel, MandPolicy};

#[derive(Debug, Clone)]
pub struct TreeOptions {
    pub parallelism: usize,
    pub follow_symlinks: bool,
    pub desired_level: LabelLevel,
    pub policy: MandPolicy,
    pub stop_on_error: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TreeStats {
    pub total: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub skipped: u64,
}

pub fn tree_apply_label(
    root: &str,
    opts: &TreeOptions,
    progress: impl Fn(u64, &str, bool) + Send + Sync,
) -> Result<TreeStats>;

pub fn tree_remove_label(
    root: &str,
    opts: &TreeOptions,
    progress: impl Fn(u64, &str, bool) + Send + Sync,
) -> Result<TreeStats>;
