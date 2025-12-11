use crate::{LockOptions, LockResult, OperationContext};
use amberlock_storage::NdjsonWriter;
use amberlock_types::*;
use amberlock_winsec as winsec;
use std::path::Path;

/// 单个对象上锁处理
pub fn process_lock(
    path: &Path,
    opts: &LockOptions,
    effective_level: LabelLevel,
    user_sid: &str,
    logger: &NdjsonWriter,
) -> Result<LockResult> {
    let ctx = OperationContext::new(path, user_sid, logger);
    let before = winsec::get_object_label(&ctx.path_str).ok();

    // 执行上锁
    let result = winsec::set_mandatory_label(&ctx.path_str, effective_level);

    let outcome = match result {
        Ok(_) => {
            let after = winsec::get_object_label(&ctx.path_str).ok();
            ctx.log_and_track(
                opts.mode,
                effective_level,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                after.as_ref().map(|s| s.sddl.clone()),  // 提取 sddl 字段
                "success",
                vec![],
            );

            if effective_level != opts.desired_level {
                Ok(LockResult::Downgraded)
            } else {
                Ok(LockResult::Success)
            }
        }
        Err(e) => {
            ctx.log_and_track(
                opts.mode,
                effective_level,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                None,
                "error",
                vec![format!("{:?}", e)],
            );
            Err(AmberlockError::from(e))
        }
    };
    outcome
}

/// 单个对象解锁处理
pub fn process_unlock(
    path: &Path,
    user_sid: &str,
    logger: &NdjsonWriter,
) -> Result<LockResult> {
    let ctx = OperationContext::new(path, user_sid, logger);
    let before = winsec::get_object_label(&ctx.path_str).ok();
    let result = winsec::remove_mandatory_label(&ctx.path_str);

    let outcome = match result {
        Ok(_) => {
            ctx.log_and_track(
                ProtectMode::ReadOnly,
                LabelLevel::Medium,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                None,
                "unlocked",
                vec![],
            );
            Ok(LockResult::Success)
        }
        Err(e) => {
            ctx.log_and_track(
                ProtectMode::ReadOnly,
                LabelLevel::Medium,
                before.as_ref().map(|s| s.sddl.clone()), // 提取 sddl 字段
                None,
                "error",
                vec![format!("{:?}", e)],
            );
            return Err(AmberlockError::from(e));
        }
    };

    outcome
}
