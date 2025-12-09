use crate::{now_iso8601, BatchOptions, LockOutcome, ProgressCallback, ProgressTracker};
use amberlock_storage::NdjsonWriter;
use amberlock_types::*;
use amberlock_winsec as winsec;
use std::path::Path;
use uuid::Uuid;


/// 操作上下文
struct OperationContext<'a> {
    path_str: String,
    target_kind: TargetKind,
    user_sid: &'a str,
    logger: &'a NdjsonWriter,
    tracker: &'a ProgressTracker,
    progress_callback: Option<&'a ProgressCallback>,
}

impl<'a> OperationContext<'a> {
    fn new(
        path: &Path,
        user_sid: &'a str,
        logger: &'a NdjsonWriter,
        tracker: &'a ProgressTracker,
        progress_callback: Option<&'a ProgressCallback>,
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
            tracker,
            progress_callback,
        }
    }

    /// 记录日志并更新追踪器
    fn log_and_track(
        &self,
        mode: ProtectMode,
        level_applied: LabelLevel,
        policy: MandPolicy,
        sddl_before: Option<String>, // 直接使用 String，不依赖未知类型
        sddl_after: Option<String>,  // 直接使用 String
        status: &str,
        errors: Vec<String>,
    ) {
        let record = LockRecord {
            id: Uuid::new_v4().to_string(),
            path: self.path_str.clone(),
            kind: self.target_kind,
            mode,
            level_applied,
            policy,
            time_utc: now_iso8601(),
            user_sid: self.user_sid.to_string(),
            owner_before: None,
            sddl_before, // 直接使用
            sddl_after,  // 直接使用
            status: status.to_string(),
            errors,
        };
        let _ = self.logger.write_record(&record);
    }

    /// 调用进度回调
    fn notify_progress(&self) {
        if let Some(callback) = self.progress_callback {
            let snapshot = self.tracker.snapshot();
            callback(&self.path_str, &snapshot);
        }
    }
}

/// 单个对象上锁处理
pub fn process_lock(
    path: &Path,
    opts: &BatchOptions,
    effective_level: LabelLevel,
    user_sid: &str,
    logger: &NdjsonWriter,
    tracker: &ProgressTracker,
    progress_callback: Option<&ProgressCallback>,
) -> Result<LockOutcome> {
    let ctx = OperationContext::new(path, user_sid, logger, tracker, progress_callback);
    let before = winsec::get_object_label(&ctx.path_str).ok();

    // 幂等性检查
    if opts.idempotent {
        if let Some(ref existing) = before {
            if existing.level == effective_level && existing.policy == opts.policy {
                tracker.mark_skipped();
                return Ok(LockOutcome::Skipped);
            }
        }
    }

    // 干跑模式
    if opts.dry_run {
        tracker.mark_success();
        return Ok(LockOutcome::Success);
    }

    // 执行上锁
    let result = winsec::set_mandatory_label(&ctx.path_str, effective_level, opts.policy);

    let outcome = match result {
        Ok(_) => {
            let after = winsec::get_object_label(&ctx.path_str).ok();
            ctx.log_and_track(
                opts.mode,
                effective_level,
                opts.policy,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                after.as_ref().map(|s| s.sddl.clone()),  // 提取 sddl 字段
                "success",
                vec![],
            );
            tracker.mark_success();

            if effective_level != opts.desired_level {
                Ok(LockOutcome::Downgraded)
            } else {
                Ok(LockOutcome::Success)
            }
        }
        Err(e) => {
            ctx.log_and_track(
                opts.mode,
                effective_level,
                opts.policy,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                None,
                "error",
                vec![format!("{:?}", e)],
            );
            tracker.mark_failed();
            Err(AmberlockError::from(e))
        }
    };

    ctx.notify_progress();
    outcome
}

/// 单个对象解锁处理
pub fn process_unlock(
    path: &Path,
    user_sid: &str,
    logger: &NdjsonWriter,
    tracker: &ProgressTracker,
    progress_callback: Option<&ProgressCallback>,
) -> Result<()> {
    let ctx = OperationContext::new(path, user_sid, logger, tracker, progress_callback);
    let before = winsec::get_object_label(&ctx.path_str).ok();
    let result = winsec::remove_mandatory_label(&ctx.path_str);

    match result {
        Ok(_) => {
            ctx.log_and_track(
                ProtectMode::ReadOnly,
                LabelLevel::Medium,
                MandPolicy::NW,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                None,
                "unlocked",
                vec![],
            );
            tracker.mark_success();
        }
        Err(e) => {
            ctx.log_and_track(
                ProtectMode::ReadOnly,
                LabelLevel::Medium,
                MandPolicy::NW,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                None,
                "error",
                vec![format!("{:?}", e)],
            );
            tracker.mark_failed();
            return Err(AmberlockError::from(e));
        }
    }

    ctx.notify_progress();
    Ok(())
}
