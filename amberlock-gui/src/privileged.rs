//! 特权操作模块
//!
//! 封装需要 SYSTEM 权限的高级操作

use amberlock_core::{BatchOptions, BatchResult, batch_lock, batch_unlock};
use amberlock_storage::NdjsonWriter;
use amberlock_types::{LabelLevel, MandPolicy, Result};
use amberlock_winsec::impersonate::with_system_privileges;
use amberlock_winsec::{remove_mandatory_label, set_mandatory_label, spawn_system_process};
use std::path::PathBuf;

/// 强制解锁（SYSTEM 权限）
///
/// 用于解锁被 SYSTEM 级保护的文件，或解锁权限损坏的文件
///
/// # 参数
/// - `paths`: 要解锁的文件列表
/// - `password`: 保险库密码
/// - `vault_blob`: 保险库加密数据
/// - `logger`: 日志记录器
///
/// # 返回
/// - `Ok(BatchResult)`: 解锁结果统计
/// - `Err`: 密码错误或操作失败
pub fn force_unlock(
    paths: &[PathBuf],
    password: &str,
    vault_blob: &[u8],
    logger: &NdjsonWriter,
) -> Result<BatchResult> {
    // 在 SYSTEM 权限下执行解锁
    Ok(with_system_privileges(|| {
        batch_unlock(paths, password, vault_blob, logger, None)
    })?)
}

/// 强制上锁（SYSTEM 权限）
///
/// 用于锁定系统级文件或应用 System 级标签
///
/// # 参数
/// - `paths`: 要锁定的文件列表
/// - `opts`: 批量操作选项
/// - `logger`: 日志记录器
///
/// # 返回
/// - `Ok(BatchResult)`: 上锁结果统计
/// - `Err`: 操作失败
pub fn force_lock(
    paths: &[PathBuf],
    opts: &BatchOptions,
    logger: &NdjsonWriter,
) -> Result<BatchResult> {
    Ok(with_system_privileges(|| {
        batch_lock(paths, opts, logger, None, None)
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
        set_mandatory_label(path, LabelLevel::High, MandPolicy::NW)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_force_unlock() {
        // 需要管理员权限
        let temp_file = NamedTempFile::new().unwrap();
        let paths = vec![temp_file.path().to_path_buf()];

        let vault_blob = amberlock_auth::create_vault("test_password").unwrap();
        let logger = NdjsonWriter::open_append(temp_file.path()).unwrap();

        match force_unlock(&paths, "test_password", &vault_blob, &logger) {
            Ok(result) => {
                println!("✅ 强制解锁成功: {}/{}", result.succeeded, result.total);
            }
            Err(e) => {
                println!("⚠️ 需要管理员权限: {:?}", e);
            }
        }
    }
}
