//! 进度跟踪模块
//!
//! 提供实时进度回调和统计功能，用于 UI 展示操作进度

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// 进度跟踪器
///
/// 线程安全的进度跟踪，支持多线程并发更新
#[derive(Clone)]
pub struct ProgressTracker {
    /// 总任务数
    total: Arc<AtomicU64>,
    /// 已完成数
    completed: Arc<AtomicU64>,
    /// 成功数
    succeeded: Arc<AtomicU64>,
    /// 失败数
    failed: Arc<AtomicU64>,
    /// 跳过数
    skipped: Arc<AtomicU64>,
    /// 开始时间
    start_time: Instant,
    /// 是否已取消
    cancelled: Arc<AtomicBool>,
}

impl ProgressTracker {
    /// 创建新的进度跟踪器
    ///
    /// # 参数
    /// - `total`: 总任务数（预估值）
    pub fn new(total: u64) -> Self {
        Self {
            total: Arc::new(AtomicU64::new(total)),
            completed: Arc::new(AtomicU64::new(0)),
            succeeded: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicU64::new(0)),
            skipped: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 标记任务成功
    pub fn mark_success(&self) {
        self.succeeded.fetch_add(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 标记任务失败
    pub fn mark_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 标记任务跳过
    pub fn mark_skipped(&self) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 获取当前进度快照
    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            total: self.total.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            succeeded: self.succeeded.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            elapsed: self.start_time.elapsed(),
            cancelled: self.is_cancelled(),
        }
    }

    /// 更新总任务数（用于递归发现更多文件时）
    pub fn update_total(&self, new_total: u64) {
        self.total.store(new_total, Ordering::Relaxed);
    }

    /// 请求取消操作
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// 检查是否已取消
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

/// 进度快照（某一时刻的状态）
#[derive(Debug, Clone)]
pub struct ProgressSnapshot {
    pub total: u64,
    pub completed: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub skipped: u64,
    pub elapsed: Duration,
    pub cancelled: bool,
}

impl ProgressSnapshot {
    /// 计算完成百分比
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.completed as f64 / self.total as f64) * 100.0
        }
    }

    /// 估算剩余时间
    pub fn eta(&self) -> Option<Duration> {
        if self.completed == 0 || self.completed >= self.total {
            return None;
        }

        let elapsed_secs = self.elapsed.as_secs_f64();
        let rate = self.completed as f64 / elapsed_secs;
        let remaining = self.total - self.completed;
        let eta_secs = remaining as f64 / rate;

        Some(Duration::from_secs_f64(eta_secs))
    }

    /// 格式化为用户友好的字符串
    pub fn format_status(&self) -> String {
        format!(
            "{}/{} ({:.1}%) - 成功: {}, 失败: {}, 跳过: {} - 耗时: {:.1}s",
            self.completed,
            self.total,
            self.percentage(),
            self.succeeded,
            self.failed,
            self.skipped,
            self.elapsed.as_secs_f64()
        )
    }
}

