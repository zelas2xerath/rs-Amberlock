use amberlock_types::{LabelLevel, MandPolicy, ProtectMode};
use std::sync::Arc;

pub mod ops;
mod progress;

pub use ops::{process_lock, process_unlock};
pub use progress::{ProgressSnapshot, ProgressTracker};

/// 上锁结果类型
pub enum LockOutcome {
    Success,
    Downgraded,
    Skipped,
}

/// 获取当前 UTC 时间戳（ISO8601）
pub fn now_iso8601() -> String {
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
/// 进度回调函数类型
///
/// # 参数
/// - `current`: 当前处理的路径
/// - `snapshot`: 当前进度快照
pub type ProgressCallback = Arc<dyn Fn(&str, &ProgressSnapshot) + Send + Sync>;

/// 批量操作选项
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// 期望的完整性级别
    pub desired_level: LabelLevel,
    /// 保护模式
    pub mode: ProtectMode,
    /// 强制策略位
    pub policy: MandPolicy,
    /// 并发度上限
    pub parallelism: usize,
    /// 干跑模式（不实际修改）
    pub dry_run: bool,
    /// 启用回滚机制
    pub enable_rollback: bool,
    /// 启用断点续执
    pub enable_checkpoint: bool,
    /// 幂等模式（重复操作不报错）
    pub idempotent: bool,
    /// 遇到错误是否立即停止
    pub stop_on_error: bool,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            desired_level: LabelLevel::High,
            mode: ProtectMode::ReadOnly,
            policy: MandPolicy::NW,
            parallelism: 4,
            dry_run: false,
            enable_rollback: true,
            enable_checkpoint: false,
            idempotent: true,
            stop_on_error: false,
        }
    }
}

/// 批量操作结果（增强版）
#[derive(Debug, Clone, Default)]
pub struct BatchResult {
    /// 总对象数
    pub total: u64,
    /// 成功数
    pub succeeded: u64,
    /// 失败数
    pub failed: u64,
    /// 降级数（期望 System 实际 High）
    pub downgraded: u64,
    /// 跳过数（已存在相同配置）
    pub skipped: u64,
    /// 是否被取消
    pub cancelled: bool,
    /// 检查点ID（如启用断点续执）
    pub checkpoint_id: Option<String>,
}

impl BatchResult {
    /// 是否完全成功
    pub fn is_success(&self) -> bool {
        self.failed == 0 && !self.cancelled
    }

    /// 是否部分成功
    pub fn is_partial_success(&self) -> bool {
        self.succeeded > 0 && (self.failed > 0 || self.cancelled)
    }
}
