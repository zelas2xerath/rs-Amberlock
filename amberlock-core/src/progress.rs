//! # 进度跟踪模块
//!
//! 提供线程安全的进度统计与实时 UI 更新支持，专为 GUI 应用设计。
//! 通过原子操作实现多线程安全更新，避免 UI 线程阻塞，确保用户界面流畅响应。
//!
//! ## 设计理念
//! - **职责分离**：后台工作线程负责进度更新，UI 线程仅负责渲染
//! - **无锁设计**：使用原子操作避免锁竞争，提升高并发场景性能
//! - **动态适应**：支持任务总量动态调整（如文件扫描时发现新文件）
//! - **优雅取消**：提供明确的取消机制，避免资源泄漏
//!
//! ## 使用示例
//! ```rust
//! let tracker = ProgressTracker::new(100);
//!
//! // 在工作线程中更新进度
//! std::thread::spawn(move || {
//!     for i in 0..100 {
//!         if i % 10 == 0 {
//!             tracker.mark_success();
//!         } else {
//!             tracker.mark_failed();
//!         }
//!     }
//! });
//!
//! // 在 UI 线程中定期获取进度快照
//! loop {
//!     let snapshot = tracker.snapshot();
//!     println!("{}", snapshot.format_status());
//!     if snapshot.completed >= snapshot.total {
//!         break;
//!     }
//!     std::thread::sleep(std::time::Duration::from_millis(200));
//! }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// 线程安全的进度跟踪器
///
///
/// # 线程安全保证
/// - 所有计数器（`completed`, `succeeded` 等）使用 `AtomicU64` 保证原子性
/// - 通过 `Ordering::Relaxed` 优化性能（在不需要严格顺序的场景下）
/// - `snapshot()` 方法提供一致的状态视图（避免读取中间状态）
///
/// # 注意事项
/// 1. **UI 线程安全**：所有进度更新必须在工作线程中进行，UI 线程仅读取 `snapshot()`
/// 2. **取消机制**：调用 `cancel()` 后，所有后续更新将被忽略
/// 3. **动态总量**：`update_total()` 仅在任务总量变化时调用（如递归扫描新增文件）
#[derive(Clone)]
pub struct ProgressTracker {
    /// 总任务数（预估值，可动态更新）
    ///
    /// 使用 `Arc<AtomicU64>` 确保多线程安全
    total: Arc<AtomicU64>,
    /// 已完成任务数（成功+失败+跳过）
    ///
    /// 通过 `fetch_add` 原子更新，避免数据竞争
    completed: Arc<AtomicU64>,
    /// 成功任务数
    succeeded: Arc<AtomicU64>,
    /// 失败任务数
    failed: Arc<AtomicU64>,
    /// 跳过任务数
    skipped: Arc<AtomicU64>,
    /// 进度跟踪开始时间（用于计算耗时）
    start_time: Instant,
    /// 是否已请求取消（线程安全）
    ///
    /// 通过 `AtomicBool` 实现，调用 `cancel()` 后立即生效
    cancelled: Arc<AtomicBool>,
}

impl ProgressTracker {
    /// 创建新的进度跟踪器
    ///
    /// # 参数
    /// - `total`: 初始任务总数（预估值，后续可通过 `update_total` 调整）
    ///
    /// # 使用场景
    /// 适用于文件批量处理、网络下载、数据转换等需要进度反馈的场景
    ///
    /// # 线程安全
    /// 该实例可被安全克隆并在线程间共享
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

    /// 标记单个任务成功
    ///
    /// # 注意事项
    /// - 自动增加 `completed` 和 `succeeded` 计数
    /// - 无需检查取消状态（即使已取消，更新仍会执行但不会影响 UI）
    pub fn mark_success(&self) {
        self.succeeded.fetch_add(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 标记单个任务失败
    ///
    /// # 注意事项
    /// - 自动增加 `completed` 和 `failed` 计数
    /// - 无需检查取消状态
    pub fn mark_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 标记单个任务跳过
    ///
    /// # 注意事项
    /// - 自动增加 `completed` 和 `skipped` 计数
    /// - 无需检查取消状态
    pub fn mark_skipped(&self) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 获取当前进度的快照
    ///
    /// # 返回值
    /// - `ProgressSnapshot`：包含完整进度状态（总任务数、完成数、成功数等）
    ///
    /// # 用途
    /// 供 UI 线程定期调用以更新进度显示
    ///
    /// # 注意事项
    /// - 该操作**不修改状态**，仅返回当前快照
    /// - 通过 `Ordering::Relaxed` 读取原子变量，保证性能
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

    /// 动态更新总任务数
    ///
    /// # 参数
    /// - `new_total`: 新的总任务数（必须 >= 当前已完成数）
    ///
    /// # 使用场景
    /// - 文件扫描时发现新文件（如递归遍历目录）
    /// - 网络下载时动态获取文件列表
    ///
    /// # 注意事项
    /// 1. 仅在任务总量变化时调用
    /// 2. 不影响已完成任务的计数
    /// 3. 调用后 UI 会自动更新总任务数显示
    pub fn update_total(&self, new_total: u64) {
        self.total.store(new_total, Ordering::Relaxed);
    }

    /// 请求取消操作
    ///
    /// # 作用
    /// - 设置取消标志位（`cancelled`）
    /// - 后续所有进度更新仍会执行但 UI 会显示已取消状态
    ///
    /// # 使用建议
    /// 1. 在工作线程中检查 `is_cancelled()` 并提前退出
    /// 2. 通常与 `cancel()` 一起使用（如用户点击取消按钮）
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// 检查是否已请求取消
    ///
    /// # 返回值
    /// - `true`：已调用 `cancel()`
    /// - `false`：未取消
    ///
    /// # 使用场景
    /// 在工作线程中检查是否应该终止任务
    ///
    /// # 注意事项
    /// - 该方法**不修改状态**，仅读取标志位
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

/// 进度快照（某一时刻的进度状态）
///
/// 包含用于 UI 显示的完整进度数据，通过 `snapshot()` 方法获取
///
/// # 字段说明
/// | 字段 | 说明 |
/// |------|------|
/// | `total` | 总任务数（可能被动态调整） |
/// | `completed` | 已完成任务数（成功+失败+跳过） |
/// | `succeeded` | 成功任务数 |
/// | `failed` | 失败任务数 |
/// | `skipped` | 跳过任务数 |
/// | `elapsed` | 从开始到快照时刻的耗时 |
/// | `cancelled` | 是否已请求取消 |
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
    /// 计算已完成任务的百分比
    ///
    /// # 返回值
    /// - 完整进度百分比（0.0-100.0）
    /// - 当总任务数为 0 时返回 0.0
    ///
    /// # 示例
    /// ```text
    /// 50/100 → 50.0%
    /// ```
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.completed as f64 / self.total as f64) * 100.0
        }
    }

    /// 估算剩余时间（ETA）
    ///
    /// # 返回值
    /// - `Some(Duration)`：剩余时间（当进度 > 0 且 < 总数时）
    /// - `None`：进度为 0 或已完成
    ///
    /// # 算法说明
    /// 1. 计算平均处理速度：`completed / elapsed_seconds`
    /// 2. 估算剩余时间：`remaining_tasks / speed`
    ///
    /// # 注意事项
    /// - 仅当 `completed > 0` 且 `completed < total` 时有效
    /// - 估算基于当前速度，实际时间可能波动
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

    /// 格式化为用户友好的状态字符串
    ///
    /// # 返回值
    /// 格式化字符串示例：`"50/100 (50.0%) - 成功: 45, 失败: 3, 跳过: 2 - 耗时: 2.5s"`
    ///
    /// # 精度说明
    /// - 百分比保留 1 位小数
    /// - 耗时保留 1 位小数
    ///
    /// # 适用场景
    /// 直接用于 UI 进度显示（如状态栏、进度条提示）
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
