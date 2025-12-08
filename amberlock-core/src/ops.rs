//! 核心业务编排模块（增强版）
//!
//! 提供完整的批量上锁/解锁功能，整合进度跟踪、回滚机制、断点续执

use crate::checkpoint::{Checkpoint, CheckpointManager};
use crate::progress::{ProgressCallback, ProgressTracker};
use crate::rollback::RollbackManager;
use amberlock_storage::NdjsonWriter;
use amberlock_types::*;
use amberlock_winsec as winsec;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use uuid::Uuid;

/// 批量操作选项（增强版）
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

/// 批量上锁（增强版）
///
/// # 参数
/// - `paths`: 要锁定的文件/目录路径列表
/// - `opts`: 批量操作选项
/// - `logger`: 日志记录器
/// - `progress_callback`: 进度回调函数（可选）
/// - `checkpoint_manager`: 断点管理器（可选）
///
/// # 特性
/// - 自动降级（System → High）
/// - 幂等性（重复上锁不报错）
/// - 回滚机制（失败时恢复）
/// - 断点续执（大规模操作）
/// - 进度回调（UI 实时更新）
pub fn batch_lock(
    paths: &[PathBuf],
    opts: &BatchOptions,
    logger: &NdjsonWriter,
    progress_callback: Option<ProgressCallback>,
    checkpoint_manager: Option<&CheckpointManager>,
) -> Result<BatchResult> {
    // 获取系统能力
    let cap = winsec::token::probe_capability()?;
    let effective_level = winsec::compute_effective_level(opts.desired_level, cap.has_se_relabel);
    let user_sid = winsec::read_user_sid().unwrap_or_default();

    // 创建进度跟踪器
    let tracker = ProgressTracker::new(paths.len() as u64);

    // 创建回滚管理器
    let rollback_manager = if opts.enable_rollback {
        let mut rm = RollbackManager::new(true);
        // 备份所有对象的原始状态
        rm.backup_batch(paths)?;
        Some(rm)
    } else {
        None
    };

    // 创建检查点
    let checkpoint = if opts.enable_checkpoint {
        let params = serde_json::json!({
            "mode": format!("{:?}", opts.mode),
            "level": format!("{:?}", effective_level),
            "policy": format!("{:?}", opts.policy),
        });
        Some(Checkpoint::new("lock", paths.len(), params))
    } else {
        None
    };

    // 配置 rayon 并发池
    rayon::ThreadPoolBuilder::new()
        .num_threads(opts.parallelism)
        .build()
        .map_err(|e| {
            (AmberlockError::Win32 {
                code: 0,
                msg: format!("Failed to create thread pool: {}", e),
            })
        })?
        .install(|| {
            // 并发处理
            let results: Vec<_> = paths
                .par_iter()
                .map(|path| {
                    // 检查取消标志
                    if tracker.is_cancelled() {
                        return Err(AmberlockError::Cancelled);
                    }

                    process_single_lock(
                        path,
                        opts,
                        effective_level,
                        &user_sid,
                        logger,
                        &tracker,
                        progress_callback.as_ref(),
                    )
                })
                .collect();

            // 汇总结果
            let mut batch_result = BatchResult {
                total: results.len() as u64,
                ..Default::default()
            };

            for result in results {
                match result {
                    Ok(LockOutcome::Success) => batch_result.succeeded += 1,
                    Ok(LockOutcome::Downgraded) => {
                        batch_result.succeeded += 1;
                        batch_result.downgraded += 1;
                    }
                    Ok(LockOutcome::Skipped) => batch_result.skipped += 1,
                    Err(AmberlockError::Cancelled) => {
                        batch_result.cancelled = true;
                        break;
                    }
                    Err(_) => {
                        batch_result.failed += 1;
                        if opts.stop_on_error {
                            break;
                        }
                    }
                }
            }

            // 处理回滚
            if batch_result.failed > 0 && opts.enable_rollback {
                if let Some(mut rm) = rollback_manager {
                    let rollback_result = rm.rollback();
                    eprintln!(
                        "回滚执行: {}/{} 成功恢复",
                        rollback_result.succeeded, rollback_result.total
                    );
                }
            } else if let Some(mut rm) = rollback_manager {
                rm.commit(); // 禁用自动回滚
            }

            // 保存检查点
            if let Some(ref ckpt) = checkpoint {
                if let Some(mgr) = checkpoint_manager {
                    let _ = mgr.save(ckpt);
                    batch_result.checkpoint_id = Some(ckpt.id.clone());
                }
            }

            Ok(batch_result)
        })
}

/// 单个对象上锁处理
fn process_single_lock(
    path: &Path,
    opts: &BatchOptions,
    effective_level: LabelLevel,
    user_sid: &str,
    logger: &NdjsonWriter,
    tracker: &ProgressTracker,
    progress_callback: Option<&ProgressCallback>,
) -> Result<LockOutcome> {
    let path_str = path.to_string_lossy().to_string();

    // 读取现有标签
    let before = winsec::get_object_label(&path_str).ok();

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
    let result = winsec::set_mandatory_label(&path_str, effective_level, opts.policy);

    let outcome = match result {
        Ok(_) => {
            let after = winsec::get_object_label(&path_str).ok();

            // 记录日志
            let record = LockRecord {
                id: Uuid::new_v4().to_string(),
                path: path_str.clone(),
                kind: if path.is_dir() {
                    TargetKind::Directory
                } else {
                    TargetKind::File
                },
                mode: opts.mode,
                level_applied: effective_level,
                policy: opts.policy,
                time_utc: now_iso8601(),
                user_sid: user_sid.to_string(),
                owner_before: None,
                sddl_before: before.as_ref().map(|s| s.sddl.clone()),
                sddl_after: after.as_ref().map(|s| s.sddl.clone()),
                status: "success".to_string(),
                errors: vec![],
            };
            let _ = logger.write_record(&record);

            tracker.mark_success();

            if effective_level != opts.desired_level {
                Ok(LockOutcome::Downgraded)
            } else {
                Ok(LockOutcome::Success)
            }
        }
        Err(e) => {
            // 记录错误日志
            let record = LockRecord {
                id: Uuid::new_v4().to_string(),
                path: path_str.clone(),
                kind: if path.is_dir() {
                    TargetKind::Directory
                } else {
                    TargetKind::File
                },
                mode: opts.mode,
                level_applied: effective_level,
                policy: opts.policy,
                time_utc: now_iso8601(),
                user_sid: user_sid.to_string(),
                owner_before: None,
                sddl_before: before.as_ref().map(|s| s.sddl.clone()),
                sddl_after: None,
                status: "error".to_string(),
                errors: vec![format!("{:?}", e)],
            };
            let _ = logger.write_record(&record);

            tracker.mark_failed();
            Err(AmberlockError::from(e))
        }
    };

    // 调用进度回调
    if let Some(callback) = progress_callback {
        let snapshot = tracker.snapshot();
        callback(&path_str, &snapshot);
    }

    outcome
}

/// 批量解锁（增强版）
pub fn batch_unlock(
    paths: &[PathBuf],
    password: &str,
    vault_blob: &[u8],
    logger: &NdjsonWriter,
    progress_callback: Option<ProgressCallback>,
) -> Result<BatchResult> {
    // 验证密码
    if !amberlock_auth::verify_password(vault_blob, password)
        .map_err(|_| AmberlockError::AuthFailed)?
    {
        return Err(AmberlockError::AuthFailed);
    }

    let tracker = ProgressTracker::new(paths.len() as u64);
    let user_sid = winsec::read_user_sid().unwrap_or_default();

    // 并发解锁
    let results: Vec<_> = paths
        .par_iter()
        .map(|path| {
            if tracker.is_cancelled() {
                return Err(AmberlockError::Cancelled);
            }

            process_single_unlock(
                path,
                &user_sid,
                logger,
                &tracker,
                progress_callback.as_ref(),
            )
        })
        .collect();

    // 汇总结果
    let mut batch_result = BatchResult {
        total: results.len() as u64,
        ..Default::default()
    };

    for result in results {
        match result {
            Ok(_) => batch_result.succeeded += 1,
            Err(AmberlockError::Cancelled) => {
                batch_result.cancelled = true;
                break;
            }
            Err(_) => batch_result.failed += 1,
        }
    }

    Ok(batch_result)
}

/// 单个对象解锁处理
fn process_single_unlock(
    path: &Path,
    user_sid: &str,
    logger: &NdjsonWriter,
    tracker: &ProgressTracker,
    progress_callback: Option<&ProgressCallback>,
) -> Result<()> {
    let path_str = path.to_string_lossy().to_string();

    let before = winsec::get_object_label(&path_str).ok();
    let result = winsec::remove_mandatory_label(&path_str);

    match result {
        Ok(_) => {
            let record = LockRecord {
                id: Uuid::new_v4().to_string(),
                path: path_str.clone(),
                kind: if path.is_dir() {
                    TargetKind::Directory
                } else {
                    TargetKind::File
                },
                mode: ProtectMode::ReadOnly,
                level_applied: LabelLevel::Medium,
                policy: MandPolicy::NW,
                time_utc: now_iso8601(),
                user_sid: user_sid.to_string(),
                owner_before: None,
                sddl_before: before.as_ref().map(|s| s.sddl.clone()),
                sddl_after: None,
                status: "unlocked".to_string(),
                errors: vec![],
            };
            let _ = logger.write_record(&record);

            tracker.mark_success();
        }
        Err(e) => {
            let record = LockRecord {
                id: Uuid::new_v4().to_string(),
                path: path_str.clone(),
                kind: if path.is_dir() {
                    TargetKind::Directory
                } else {
                    TargetKind::File
                },
                mode: ProtectMode::ReadOnly,
                level_applied: LabelLevel::Medium,
                policy: MandPolicy::NW,
                time_utc: now_iso8601(),
                user_sid: user_sid.to_string(),
                owner_before: None,
                sddl_before: before.as_ref().map(|s| s.sddl.clone()),
                sddl_after: None,
                status: "error".to_string(),
                errors: vec![format!("{:?}", e)],
            };
            let _ = logger.write_record(&record);

            tracker.mark_failed();
            return Err(AmberlockError::from(e));
        }
    }

    if let Some(callback) = progress_callback {
        let snapshot = tracker.snapshot();
        callback(&path_str, &snapshot);
    }

    Ok(())
}

/// 上锁结果类型
enum LockOutcome {
    Success,
    Downgraded,
    Skipped,
}

/// 获取当前 UTC 时间戳（ISO8601）
fn now_iso8601() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_options_default() {
        let opts = BatchOptions::default();
        assert_eq!(opts.desired_level, LabelLevel::High);
        assert_eq!(opts.mode, ProtectMode::ReadOnly);
        assert!(opts.idempotent);
        assert!(opts.enable_rollback);
    }

    #[test]
    fn test_batch_result_status() {
        let success = BatchResult {
            total: 10,
            succeeded: 10,
            failed: 0,
            ..Default::default()
        };
        assert!(success.is_success());

        let partial = BatchResult {
            total: 10,
            succeeded: 7,
            failed: 3,
            ..Default::default()
        };
        assert!(partial.is_partial_success());
    }
}
