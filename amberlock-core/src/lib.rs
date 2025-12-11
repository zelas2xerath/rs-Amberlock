use std::fmt::{Display, Formatter};
use std::path::Path;
use uuid::Uuid;
use amberlock_storage::NdjsonWriter;
use amberlock_types::{LabelLevel, LockRecord, ProtectMode, TargetKind};

pub mod ops;
pub mod privileged;

pub use ops::{
    process_lock,
    process_unlock,
    batch_process_lock,
    batch_process_unlock,
};
pub use privileged::{
    force_lock,
    force_unlock,
    repair_file_permissions,
};

/// 上锁结果类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockResult {
    /// 操作成功
    Success,
    /// 已降级处理（例如 System → High）
    Downgraded,
    /// 已跳过
    Skipped,
}

impl Display for LockResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LockResult::Success => write!(f, "操作成功"),
            LockResult::Downgraded => write!(f, "已降级处理"),
            LockResult::Skipped => write!(f, "已跳过"),
        }
    }
}

/// 批量操作结果统计
#[derive(Debug, Clone, Default)]
pub struct BatchResult {
    /// 成功数量
    pub success_count: usize,
    /// 失败数量
    pub failed_count: usize,
    /// 降级数量
    pub downgraded_count: usize,
    /// 总数量
    pub total_count: usize,
}

impl Display for BatchResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "操作完成：成功 {} 个，失败 {} 个，降级 {} 个（共 {} 个）",
            self.success_count, self.failed_count, self.downgraded_count, self.total_count
        )
    }
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

/// 操作上下文
pub struct OperationContext<'a> {
    pub path_str: String,
    pub target_kind: TargetKind,
    pub user_sid: &'a str,
    pub logger: &'a NdjsonWriter,
}

impl<'a> OperationContext<'a> {
    pub fn new(
        path: &Path,
        user_sid: &'a str,
        logger: &'a NdjsonWriter,
    ) -> Self {
        Self {
            path_str: path.to_string_lossy().to_string(),
            target_kind: if path.is_dir() {
                TargetKind::Directory
            } else {
                TargetKind::File
            },
            user_sid,
            logger,
        }
    }

    /// 记录日志
    pub fn log_and_track(
        &self,
        mode: ProtectMode,
        level_applied: LabelLevel,
        sddl_before: Option<String>,
        sddl_after: Option<String>,
        status: &str,
        errors: Vec<String>,
    ) {
        let record = LockRecord {
            id: Uuid::new_v4().to_string(),
            path: self.path_str.clone(),
            kind: self.target_kind,
            mode,
            level_applied,
            time_utc: now_iso8601(),
            user_sid: self.user_sid.to_string(),
            owner_before: None,
            sddl_before,
            sddl_after,
            status: status.to_string(),
            errors,
        };
        let _ = self.logger.write_record(&record);
    }
}

/// 获取当前 UTC 时间戳（ISO8601）
pub fn now_iso8601() -> String {
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}