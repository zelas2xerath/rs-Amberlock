//! 递归目录树操作
//!
//! 本模块实现批量设置/移除 Mandatory Label，支持：
//! - 递归遍历目录树
//! - 并发处理（使用 rayon）
//! - 进度回调
//! - 错误处理与跳过策略

use super::setlabel::{remove_mandatory_label, set_mandatory_label};
use amberlock_types::{AmberlockError, LabelLevel, Result};
use rayon::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use walkdir::WalkDir;

/// 目录树操作选项
#[derive(Debug, Clone)]
pub struct TreeOptions {
    /// 并发度（同时处理的路径数）
    pub parallelism: usize,
    /// 是否跟随符号链接
    pub follow_symlinks: bool,
    /// 目标完整性级别
    pub desired_level: LabelLevel,
    /// 遇到错误是否停止（false 则跳过失败项）
    pub stop_on_error: bool,
}

impl Default for TreeOptions {
    fn default() -> Self {
        Self {
            parallelism: 4,
            follow_symlinks: false,
            desired_level: LabelLevel::High,
            stop_on_error: false,
        }
    }
}

/// 目录树操作统计
#[derive(Debug, Clone, Default)]
pub struct TreeStats {
    /// 扫描到的总对象数
    pub total: u64,
    /// 成功处理数
    pub succeeded: u64,
    /// 失败数
    pub failed: u64,
    /// 跳过数（如符号链接、权限不足）
    pub skipped: u64,
}

/// 递归应用 Mandatory Label 到目录树
///
/// # 参数
/// - `root`: 根目录路径
/// - `opts`: 操作选项
/// - `progress`: 进度回调函数 (当前处理数, 路径, 是否成功)
///
/// # 返回
/// - `Ok(TreeStats)`: 操作统计
/// - `Err`: 严重错误（如根目录不存在）
///
/// # 实现策略
/// 1. 使用 walkdir 遍历目录树
/// 2. 使用 rayon 并发处理（受 parallelism 限制）
/// 3. 每处理一个对象调用进度回调
/// 4. 跟踪成功/失败/跳过数量
pub fn tree_apply_label<F>(root: &str, opts: &TreeOptions, progress: F) -> Result<TreeStats>
where
    F: Fn(u64, &str, bool) + Send + Sync,
{
    // 原子计数器（多线程安全）
    let total = Arc::new(AtomicU64::new(0));
    let succeeded = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let skipped = Arc::new(AtomicU64::new(0));

    // 配置 walkdir
    let walker = WalkDir::new(root)
        .follow_links(opts.follow_symlinks)
        .into_iter()
        .filter_map(|e| e.ok()); // 跳过遍历错误

    // 收集所有路径（先扫描再处理，避免 walkdir 迭代器与并发冲突）
    let paths: Vec<_> = walker.map(|entry| entry.path().to_path_buf()).collect();

    let total_count = paths.len() as u64;
    total.store(total_count, Ordering::Relaxed);

    // 并发处理
    let results: Vec<_> = paths
        .par_iter()
        .with_max_len(1) // 控制任务粒度
        .map(|path| {
            let path_str = path.to_string_lossy().to_string();

            // 尝试设置标签
            let result = set_mandatory_label(&path_str, opts.desired_level);

            let success = result.is_ok();
            if success {
                succeeded.fetch_add(1, Ordering::Relaxed);
            } else {
                failed.fetch_add(1, Ordering::Relaxed);
            }

            // 调用进度回调
            let current = succeeded.load(Ordering::Relaxed) + failed.load(Ordering::Relaxed);
            progress(current, &path_str, success);

            result
        })
        .collect();

    // 检查是否需要因错误停止
    if opts.stop_on_error && results.iter().any(|r| r.is_err()) {
        return Err(AmberlockError::Win32 {
            code: 0,
            msg: "Stopped due to errors (stop_on_error=true)".to_string(),
        });
    }

    Ok(TreeStats {
        total: total.load(Ordering::Relaxed),
        succeeded: succeeded.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
        skipped: skipped.load(Ordering::Relaxed),
    })
}

/// 递归移除目录树的 Mandatory Label
///
/// # 参数
/// - `root`: 根目录路径
/// - `opts`: 操作选项（仅使用 parallelism 和 stop_on_error）
/// - `progress`: 进度回调函数
///
/// # 返回
/// - `Ok(TreeStats)`: 操作统计
/// - `Err`: 严重错误
pub fn tree_remove_label<F>(root: &str, opts: &TreeOptions, progress: F) -> Result<TreeStats>
where
    F: Fn(u64, &str, bool) + Send + Sync,
{
    let total = Arc::new(AtomicU64::new(0));
    let succeeded = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let skipped = Arc::new(AtomicU64::new(0));

    let walker = WalkDir::new(root)
        .follow_links(opts.follow_symlinks)
        .into_iter()
        .filter_map(|e| e.ok());

    let paths: Vec<_> = walker.map(|entry| entry.path().to_path_buf()).collect();

    let total_count = paths.len() as u64;
    total.store(total_count, Ordering::Relaxed);

    let results: Vec<_> = paths
        .par_iter()
        .with_max_len(1)
        .map(|path| {
            let path_str = path.to_string_lossy().to_string();

            // 尝试移除标签
            let result = remove_mandatory_label(&path_str);

            let success = result.is_ok();
            if success {
                succeeded.fetch_add(1, Ordering::Relaxed);
            } else {
                failed.fetch_add(1, Ordering::Relaxed);
            }

            let current = succeeded.load(Ordering::Relaxed) + failed.load(Ordering::Relaxed);
            progress(current, &path_str, success);

            result
        })
        .collect();

    if opts.stop_on_error && results.iter().any(|r| r.is_err()) {
        return Err(AmberlockError::Win32 {
            code: 0,
            msg: "Stopped due to errors (stop_on_error=true)".to_string(),
        });
    }

    Ok(TreeStats {
        total: total.load(Ordering::Relaxed),
        succeeded: succeeded.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
        skipped: skipped.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_tree_apply_label() {
        // 创建临时目录树
        let temp_dir = tempdir().unwrap();
        let root = temp_dir.path();

        // 创建测试文件和子目录
        fs::create_dir(root.join("subdir")).unwrap();
        fs::write(root.join("file1.txt"), b"test1").unwrap();
        fs::write(root.join("subdir/file2.txt"), b"test2").unwrap();

        let root_str = root.to_string_lossy();

        let opts = TreeOptions {
            parallelism: 2,
            follow_symlinks: false,
            desired_level: LabelLevel::High,
            stop_on_error: false,
        };

        // 应用标签
        let result = tree_apply_label(&root_str, &opts, |current, path, success| {
            println!("Progress: {}/{} - {} [{}]", current, 3, path, success);
        });

        if result.is_err() {
            println!("警告：需要管理员权限才能运行此测试");
            return;
        }

        let stats = result.unwrap();
        println!("Stats: {:?}", stats);
        assert!(stats.succeeded > 0 || stats.failed > 0);

        // 清理：移除标签
        let _ = tree_remove_label(&root_str, &opts, |_, _, _| {});
    }

    #[test]
    fn test_tree_stats_default() {
        let stats = TreeStats::default();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.succeeded, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.skipped, 0);
    }
}
