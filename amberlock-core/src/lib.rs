//! AmberLock 核心业务编排库
//!
//! 提供完整的文件锁定/解锁业务逻辑，包括：
//! - 批量操作（并发、幂等、回滚）
//! - 递归目录处理
//! - 进度跟踪和回调
//! - 断点续执
//! - 能力探测
//!
//! # 使用示例
//!
//! ```rust,no_run
//! use amberlock_core::*;
//! use amberlock_storage::NdjsonWriter;
//! use std::path::PathBuf;
//!
//! // 创建日志记录器
//! let logger = NdjsonWriter::open_append("logs/operations.ndjson")?;
//!
//! // 配置批量上锁选项
//! let opts = BatchOptions {
//!     desired_level: LabelLevel::High,
//!     mode: ProtectMode::ReadOnly,
//!     policy: MandPolicy::NW,
//!     parallelism: 4,
//!     dry_run: false,
//!     enable_rollback: true,
//!     enable_checkpoint: false,
//!     idempotent: true,
//!     stop_on_error: false,
//! };
//!
//! // 待锁定的文件列表
//! let paths = vec![
//!     PathBuf::from("C:\\Documents\\secret.txt"),
//!     PathBuf::from("C:\\Data\\config.json"),
//! ];
//!
//! // 执行批量上锁
//! let result = batch_lock(
//!     &paths,
//!     &opts,
//!     &logger,
//!     None, // 无进度回调
//!     None, // 无断点管理器
//! )?;
//!
//! println!("上锁完成: {}/{} 成功", result.succeeded, result.total);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
mod checkpoint;
pub mod inspect;
pub mod ops;
mod progress;
mod recursive;
mod rollback;

// 公共导出
pub use amberlock_types::*;
pub use checkpoint::{Checkpoint, CheckpointManager};
pub use inspect::{InspectReport, probe_capability};
pub use ops::{BatchOptions, BatchResult, batch_lock, batch_unlock};
pub use progress::{ProgressCallback, ProgressSnapshot, ProgressTracker};
pub use recursive::{
    RecursiveOptions, RecursiveResult, recursive_apply_label, recursive_remove_label,
};
pub use rollback::{ObjectBackup, RollbackManager, RollbackResult};
