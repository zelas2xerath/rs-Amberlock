//! 特权操作模块
//!
//! 封装需要 SYSTEM 权限的高级操作

use amberlock_core::{process_lock, process_unlock, LockOptions, LockResult};
use amberlock_storage::NdjsonWriter;
use amberlock_types::{LabelLevel, Result};
use amberlock_winsec::{
    impersonate::with_system_privileges,
    remove_mandatory_label, set_mandatory_label, spawn_system_process
};
use std::path::Path;

/// 强制解锁（SYSTEM 权限）
///
/// 用于解锁被 SYSTEM 级保护的文件，或解锁权限损坏的文件
/// New API Fix Side
pub fn force_unlock(
    path: &Path,
    user_sid: &str,
    logger: &NdjsonWriter,
) -> Result<LockResult> {
    // 在 SYSTEM 权限下执行解锁
    with_system_privileges(|| {
        process_unlock(path, user_sid, logger)
    })
}

/// 强制上锁（SYSTEM 权限）
///
/// 用于锁定系统级文件或应用 System 级标签
/// New API Fix Side
pub fn force_lock(
    path: &Path,
    opts: &LockOptions,
    effective_level: LabelLevel,
    user_sid: &str,
    logger: &NdjsonWriter,
) -> Result<LockResult> {
    Ok(with_system_privileges(|| {
        process_lock(path, opts, effective_level, user_sid, logger)
    })?)
}

/// 修复文件权限
///
/// 当文件的 DACL/SACL 损坏时，使用 SYSTEM 权限修复
///
/// # 参数
/// - `path`: 要修复的文件路径
///
/// # 返回
/// - `Ok(())`: 修复成功
/// - `Err`: 修复失败
pub fn repair_file_permissions(path: &str) -> Result<()> {
    with_system_privileges(|| {
        // 1. 移除现有标签
        remove_mandatory_label(path)?;

        // 2. 重新设置默认标签
        set_mandatory_label(path, LabelLevel::High)?;

        Ok(())
    })
}

/// 创建 SYSTEM 权限的维护进程
///
/// 启动一个以 SYSTEM 权限运行的命令行窗口，供高级操作使用
///
/// # 返回
/// - `Ok(u32)`: 新进程的 PID
/// - `Err`: 创建失败
pub fn spawn_maintenance_shell() -> Result<u32> {
    // 启动带标题的 cmd.exe
    let cmd = r#"cmd.exe /k title AmberLock Maintenance Shell (SYSTEM) && echo. && echo *** SYSTEM 权限维护模式 *** && echo. && echo 当前权限: SYSTEM && echo 请谨慎操作！ && echo."#;

    spawn_system_process(cmd)
}
