use crate::{BatchResult, LockOptions, LockResult, OperationContext};
use amberlock_storage::NdjsonWriter;
use amberlock_types::*;
use amberlock_winsec as winsec;
use std::path::Path;

// ============================================================================
// 任务 4.1：特权检查前置
// ============================================================================

/// 检查执行锁定操作所需的特权
///
/// # 参数
/// - `level`: 目标完整性级别
///
/// # 返回
/// - `Ok(())`: 特权检查通过
/// - `Err`: 缺少必要特权
fn check_lock_privileges(level: LabelLevel) -> Result<()> {
    let capability = winsec::probe_capability()?;

    // SeSecurityPrivilege 是必需的
    if !capability.has_se_security {
        return Err(AmberlockError::PrivilegeMissing(
            "SeSecurityPrivilege - 需要以管理员身份运行程序",
        ));
    }

    // 设置 System 级别需要 SeRelabelPrivilege
    if level == LabelLevel::System && !capability.has_se_relabel {
        return Err(AmberlockError::ElevationRequired);
    }

    Ok(())
}

/// 检查执行解锁操作所需的特权
fn check_unlock_privileges() -> Result<()> {
    let capability = winsec::probe_capability()?;

    if !capability.has_se_security {
        return Err(AmberlockError::PrivilegeMissing(
            "SeSecurityPrivilege - 需要以管理员身份运行程序",
        ));
    }

    Ok(())
}

// ============================================================================
// 任务 4.3：单对象操作（不递归）
// ============================================================================

/// 单个对象上锁处理
///
/// # 参数
/// - `path`: 文件或文件夹路径
/// - `opts`: 锁定选项
/// - `effective_level`: 有效完整性级别
/// - `user_sid`: 用户 SID
/// - `logger`: 日志记录器
///
/// # 注意
/// 任务 4.3：只对路径本身操作，不递归处理文件夹内容
pub fn process_lock(
    path: &Path,
    opts: &LockOptions,
    effective_level: LabelLevel,
    user_sid: &str,
    logger: &NdjsonWriter,
) -> Result<LockResult> {
    // 任务 4.1：前置特权检查
    check_lock_privileges(effective_level)?;

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
                before.as_ref().map(|s| s.sddl.clone()),
                after.as_ref().map(|s| s.sddl.clone()),
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
                before.as_ref().map(|s| s.sddl.clone()),
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
///
/// # 注意
/// 任务 4.3：只对路径本身操作，不递归处理文件夹内容
pub fn process_unlock(path: &Path, user_sid: &str, logger: &NdjsonWriter) -> Result<LockResult> {
    // 任务 4.1：前置特权检查
    check_unlock_privileges()?;

    let ctx = OperationContext::new(path, user_sid, logger);
    let before = winsec::get_object_label(&ctx.path_str).ok();
    let result = winsec::remove_mandatory_label(&ctx.path_str);

    let outcome = match result {
        Ok(_) => {
            ctx.log_and_track(
                ProtectMode::ReadOnly,
                LabelLevel::Medium,
                before.as_ref().map(|s| s.sddl.clone()),
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
                before.as_ref().map(|s| s.sddl.clone()),
                None,
                "error",
                vec![format!("{:?}", e)],
            );
            Err(AmberlockError::from(e))
        }
    };

    outcome
}

// ============================================================================
// 任务 7.2：批量操作支持
// ============================================================================

/// 批量锁定操作
///
/// # 参数
/// - `paths`: 要锁定的路径列表
/// - `opts`: 锁定选项
/// - `effective_level`: 有效完整性级别
/// - `user_sid`: 用户 SID
/// - `logger`: 日志记录器
///
/// # 返回
/// 批量操作结果统计
///
/// # 行为
/// - 对列表中的每个路径独立执行锁定操作
/// - 单个路径失败不影响其他路径的处理
/// - 所有错误都记录到日志，但不中断批量操作
pub fn batch_process_lock(
    paths: &[impl AsRef<Path>],
    opts: &LockOptions,
    effective_level: LabelLevel,
    user_sid: &str,
    logger: &NdjsonWriter,
) -> BatchResult {
    let mut result = BatchResult {
        total_count: paths.len(),
        ..Default::default()
    };

    for path in paths {
        match process_lock(path.as_ref(), opts, effective_level, user_sid, logger) {
            Ok(LockResult::Success) => result.success_count += 1,
            Ok(LockResult::Downgraded) => {
                result.success_count += 1;
                result.downgraded_count += 1;
            }
            Ok(LockResult::Skipped) => {}
            Err(_) => result.failed_count += 1,
        }
    }

    result
}

/// 批量解锁操作
///
/// # 参数
/// - `paths`: 要解锁的路径列表
/// - `user_sid`: 用户 SID
/// - `logger`: 日志记录器
///
/// # 返回
/// 批量操作结果统计
pub fn batch_process_unlock(
    paths: &[impl AsRef<Path>],
    user_sid: &str,
    logger: &NdjsonWriter,
) -> BatchResult {
    let mut result = BatchResult {
        total_count: paths.len(),
        ..Default::default()
    };

    for path in paths {
        match process_unlock(path.as_ref(), user_sid, logger) {
            Ok(LockResult::Success) => result.success_count += 1,
            Ok(LockResult::Downgraded) => {
                result.success_count += 1;
                result.downgraded_count += 1;
            }
            Ok(LockResult::Skipped) => {}
            Err(_) => result.failed_count += 1,
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn test_batch_result_display() {
        let result = BatchResult {
            success_count: 5,
            failed_count: 1,
            downgraded_count: 2,
            total_count: 6,
        };

        let display = format!("{}", result);
        assert!(display.contains("成功 5 个"));
        assert!(display.contains("失败 1 个"));
        assert!(display.contains("降级 2 个"));
        println!("✅ 批量结果显示测试通过");
    }

    #[test]
    #[ignore] // 需要管理员权限
    fn test_batch_lock() {
        let temp_dir = TempDir::new().expect("创建临时目录失败");
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");

        File::create(&file1).expect("创建文件1失败");
        File::create(&file2).expect("创建文件2失败");

        let paths = vec![file1, file2];
        let opts = LockOptions::default();

        let logger = NdjsonWriter::open_append(temp_dir.path().join("test.log"))
            .expect("创建日志失败");

        let user_sid = winsec::read_user_sid().unwrap_or_default();
        let effective_level = winsec::compute_effective_level(
            opts.desired_level,
            winsec::probe_capability().unwrap().has_se_relabel,
        );

        let result = batch_process_lock(&paths, &opts, effective_level, &user_sid, &logger);

        println!("批量锁定结果: {}", result);
        assert_eq!(result.total_count, 2);
    }
}