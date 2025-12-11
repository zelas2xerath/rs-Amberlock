use std::path::Path;
use uuid::Uuid;
use amberlock_storage::NdjsonWriter;
use amberlock_types::{LabelLevel, LockRecord, ProtectMode, TargetKind};

pub mod ops;

pub use ops::{process_lock, process_unlock};

/// 上锁结果类型
pub enum LockResult {
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

/// 操作上下文
pub struct OperationContext<'a> {
    path_str: String,
    target_kind: TargetKind,
    user_sid: &'a str,
    logger: &'a NdjsonWriter,
}

impl<'a> OperationContext<'a> {
    fn new(
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

    /// 记录日志并更新追踪器
    fn log_and_track(
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