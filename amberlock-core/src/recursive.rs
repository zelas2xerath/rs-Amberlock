//! 递归目录操作模块
//!
//! 提供目录树遍历和批量操作功能，整合 winsec::tree_apply_label

use crate::errors::{CoreError, Result};
use crate::progress::{ProgressCallback, ProgressTracker};
use crate::rollback::RollbackManager;
use amberlock_storage::NdjsonWriter;
use amberlock_types::*;
use amberlock_winsec as winsec;
use std::path::Path;
use time::OffsetDateTime;
use uuid::Uuid;

/// 递归操作选项
#[derive(Debug, Clone)]
pub struct RecursiveOptions {
    /// 目标完整性级别
    pub desired_level: LabelLevel,
    /// 保护模式
    pub mode: ProtectMode,
    /// 强制策略
    pub policy: MandPolicy,
    /// 并发度
    pub parallelism: usize,
    /// 是否跟随符号链接
    pub follow_symlinks: bool,
    /// 遇到错误是否停止
    pub stop_on_error: bool,
    /// 干跑模式（不实际修改）
    pub dry_run: bool,
    /// 是否启用回滚
    pub enable_rollback: bool,
}

impl Default for RecursiveOptions {
    fn default() -> Self {
        Self {
            desired_level: LabelLevel::High,
            mode: ProtectMode::ReadOnly,
            policy: MandPolicy::NW,
            parallelism: 4,
            follow_symlinks: false,
            stop_on_error: false,
            dry_run: false,
            enable_rollback: true,
        }
    }
}

/// 递归操作结果
#[derive(Debug, Clone, Default)]
pub struct RecursiveResult {
    /// 总对象数
    pub total: u64,
    /// 成功数
    pub succeeded: u64,
    /// 失败数
    pub failed: u64,
    /// 跳过数
    pub skipped: u64,
    /// 是否被取消
    pub cancelled: bool,
}

impl RecursiveResult {
    /// 是否完全成功
    pub fn is_success(&self) -> bool {
        self.failed == 0 && !self.cancelled
    }

    /// 是否部分成功
    pub fn is_partial_success(&self) -> bool {
        self.succeeded > 0 && (self.failed > 0 || self.cancelled)
    }
}

/// 递归应用标签到目录树
///
/// # 参数
/// - `root`: 根目录路径
/// - `opts`: 递归选项
/// - `logger`: 日志记录器
/// - `progress_callback`: 进度回调（可选）
///
/// # 返回
/// - `Ok(RecursiveResult)`: 操作统计
/// - `Err`: 严重错误
pub fn recursive_apply_label(
    root: &Path,
    opts: &RecursiveOptions,
    logger: &NdjsonWriter,
    progress_callback: Option<ProgressCallback>,
) -> Result<RecursiveResult> {
    // 卷根特殊处理
    if is_volume_root(root) {
        return handle_volume_root_warning(root, opts);
    }

    // 获取系统能力
    let cap = winsec::token::probe_capability()?;
    let effective_level = winsec::compute_effective_level(opts.desired_level, cap.has_se_relabel);

    // 创建进度跟踪器
    let tracker = ProgressTracker::new(0); // 初始为0，遍历时更新

    // 创建回滚管理器
    let mut rollback_manager = RollbackManager::new(opts.enable_rollback);

    // 配置 winsec 递归选项
    let tree_opts = winsec::TreeOptions {
        parallelism: opts.parallelism,
        follow_symlinks: opts.follow_symlinks,
        desired_level: effective_level,
        policy: opts.policy,
        stop_on_error: opts.stop_on_error,
    };

    // 进度回调封装
    let progress_fn = {
        let tracker = tracker.clone();
        let callback = progress_callback.clone();
        move |current: u64, path: &str, success: bool| {
            if success {
                tracker.mark_success();
            } else {
                tracker.mark_failed();
            }

            if let Some(ref cb) = callback {
                let snapshot = tracker.snapshot();
                cb(path, &snapshot);
            }
        }
    };

    // 执行递归操作
    let root_str = root.to_string_lossy().to_string();

    let tree_stats = if opts.dry_run {
        // 干跑模式：仅扫描不修改
        dry_run_tree_scan(&root_str, &tree_opts, progress_fn)?
    } else {
        // 正常模式：应用标签
        winsec::tree_apply_label(&root_str, &tree_opts, progress_fn)?
    };

    // 记录日志
    log_recursive_operation(
        &root_str,
        opts,
        effective_level,
        &tree_stats,
        logger,
    )?;

    // 检查是否取消
    if tracker.is_cancelled() {
        rollback_manager.rollback();
        return Ok(RecursiveResult {
            total: tree_stats.total,
            succeeded: tree_stats.succeeded,
            failed: tree_stats.failed,
            skipped: tree_stats.skipped,
            cancelled: true,
        });
    }

    // 成功，提交（禁用自动回滚）
    if !opts.dry_run {
        rollback_manager.commit();
    }

    Ok(RecursiveResult {
        total: tree_stats.total,
        succeeded: tree_stats.succeeded,
        failed: tree_stats.failed,
        skipped: tree_stats.skipped,
        cancelled: false,
    })
}

/// 递归移除目录树的标签
pub fn recursive_remove_label(
    root: &Path,
    opts: &RecursiveOptions,
    logger: &NdjsonWriter,
    progress_callback: Option<ProgressCallback>,
) -> Result<RecursiveResult> {
    let tracker = ProgressTracker::new(0);

    let tree_opts = winsec::TreeOptions {
        parallelism: opts.parallelism,
        follow_symlinks: opts.follow_symlinks,
        desired_level: LabelLevel::Medium, // 移除时不重要
        policy: opts.policy,
        stop_on_error: opts.stop_on_error,
    };

    let progress_fn = {
        let tracker = tracker.clone();
        let callback = progress_callback.clone();
        move |_current: u64, path: &str, success: bool| {
            if success {
                tracker.mark_success();
            } else {
                tracker.mark_failed();
            }

            if let Some(ref cb) = callback {
                let snapshot = tracker.snapshot();
                cb(path, &snapshot);
            }
        }
    };

    let root_str = root.to_string_lossy().to_string();
    let tree_stats = winsec::tree_remove_label(&root_str, &tree_opts, progress_fn)?;

    // 记录解锁日志
    log_recursive_unlock(&root_str, &tree_stats, logger)?;

    Ok(RecursiveResult {
        total: tree_stats.total,
        succeeded: tree_stats.succeeded,
        failed: tree_stats.failed,
        skipped: tree_stats.skipped,
        cancelled: tracker.is_cancelled(),
    })
}

// === 辅助函数 ===

/// 卷根警告处理
fn handle_volume_root_warning(root: &Path, opts: &RecursiveOptions) -> Result<RecursiveResult> {
    // 卷根只允许只读模式 + NW 策略
    if opts.mode != ProtectMode::ReadOnly || opts.policy != MandPolicy::NW {
        return Err(CoreError::WinSec(amberlock_winsec::error::WinSecError::Win32 {
            code: 0,
            msg: "卷根仅支持只读模式 + NW 策略，以防止系统异常".to_string(),
        }));
    }

    // 这里应该显示二次确认对话框，但在 core 层无法实现
    // 交由 GUI 层在调用前处理
    Ok(RecursiveResult {
        total: 0,
        succeeded: 0,
        failed: 0,
        skipped: 0,
        cancelled: true, // 标记为取消，要求上层确认
    })
}

/// 检查是否为卷根
fn is_volume_root(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let path_str = path.to_string_lossy();
        if path_str.len() == 3 {
            let bytes = path_str.as_bytes();
            bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
        } else {
            false
        }
    }

    #[cfg(not(windows))]
    {
        path == Path::new("/")
    }
}

/// 干跑模式目录扫描
fn dry_run_tree_scan<F>(
    root: &str,
    opts: &winsec::TreeOptions,
    progress: F,
) -> Result<winsec::TreeStats>
where
    F: Fn(u64, &str, bool) + Send + Sync,
{
    use walkdir::WalkDir;

    let mut total = 0u64;
    let walker = WalkDir::new(root)
        .follow_links(opts.follow_symlinks)
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in walker {
        total += 1;
        progress(total, &entry.path().to_string_lossy(), true);
    }

    Ok(winsec::TreeStats {
        total,
        succeeded: total,
        failed: 0,
        skipped: 0,
    })
}

/// 记录递归操作日志
fn log_recursive_operation(
    root: &str,
    opts: &RecursiveOptions,
    effective_level: LabelLevel,
    stats: &winsec::TreeStats,
    logger: &NdjsonWriter,
) -> Result<()> {
    let record = LockRecord {
        id: Uuid::new_v4().to_string(),
        path: root.to_string(),
        kind: TargetKind::Directory,
        mode: opts.mode,
        level_applied: effective_level,
        policy: opts.policy,
        time_utc: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        user_sid: winsec::read_user_sid().unwrap_or_default(),
        owner_before: None,
        sddl_before: None,
        sddl_after: None,
        status: format!(
            "recursive: {}/{} succeeded",
            stats.succeeded, stats.total
        ),
        errors: if stats.failed > 0 {
            vec![format!("{} objects failed", stats.failed)]
        } else {
            vec![]
        },
    };

    logger.write_record(&record)?;
    Ok(())
}

/// 记录递归解锁日志
fn log_recursive_unlock(
    root: &str,
    stats: &winsec::TreeStats,
    logger: &NdjsonWriter,
) -> Result<()> {
    let record = LockRecord {
        id: Uuid::new_v4().to_string(),
        path: root.to_string(),
        kind: TargetKind::Directory,
        mode: ProtectMode::ReadOnly,
        level_applied: LabelLevel::Medium,
        policy: MandPolicy::NW,
        time_utc: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        user_sid: winsec::read_user_sid().unwrap_or_default(),
        owner_before: None,
        sddl_before: None,
        sddl_after: None,
        status: format!(
            "recursive_unlock: {}/{} succeeded",
            stats.succeeded, stats.total
        ),
        errors: vec![],
    };

    logger.write_record(&record)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_volume_root() {
        #[cfg(windows)]
        {
            assert!(is_volume_root(Path::new("C:\\")));
            assert!(is_volume_root(Path::new("D:\\")));
            assert!(!is_volume_root(Path::new("C:\\Windows")));
        }

        #[cfg(not(windows))]
        {
            assert!(is_volume_root(Path::new("/")));
            assert!(!is_volume_root(Path::new("/home")));
        }
    }

    #[test]
    fn test_recursive_options_default() {
        let opts = RecursiveOptions::default();
        assert_eq!(opts.desired_level, LabelLevel::High);
        assert_eq!(opts.mode, ProtectMode::ReadOnly);
        assert!(opts.policy.contains(MandPolicy::NW));
        assert_eq!(opts.parallelism, 4);
    }

    #[test]
    fn test_recursive_result_status() {
        let success = RecursiveResult {
            total: 10,
            succeeded: 10,
            failed: 0,
            skipped: 0,
            cancelled: false,
        };
        assert!(success.is_success());
        assert!(!success.is_partial_success());

        let partial = RecursiveResult {
            total: 10,
            succeeded: 7,
            failed: 3,
            skipped: 0,
            cancelled: false,
        };
        assert!(!partial.is_success());
        assert!(partial.is_partial_success());
    }
}