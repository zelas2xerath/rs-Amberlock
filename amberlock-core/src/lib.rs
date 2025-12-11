use amberlock_types::{LabelLevel, ProtectMode};

pub mod ops;

pub use ops::{process_lock, process_unlock};

/// 上锁结果类型
pub enum LockOutcome {
    Success,
    Downgraded,
    Skipped,
}

/// 批量操作选项
#[derive(Debug, Clone)]
pub struct LockOptions {
    /// 期望的完整性级别
    pub desired_level: LabelLevel,
    /// 保护模式
    pub mode: ProtectMode,
    /// 并发度上限
    pub parallelism: usize,
}

impl Default for LockOptions {
    fn default() -> Self {
        Self {
            desired_level: LabelLevel::High,
            mode: ProtectMode::ReadOnly,
            parallelism: 4,
        }
    }
}

/// 获取当前 UTC 时间戳（ISO8601）
pub fn now_iso8601() -> String {
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}