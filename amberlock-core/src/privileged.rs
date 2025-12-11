//! 特权操作模块
//!
//! 封装需要 SYSTEM 权限的高级操作

use crate::{LockOptions, LockResult, OperationContext};
use amberlock_storage::NdjsonWriter;
use amberlock_types::{LabelLevel, Result};
use amberlock_winsec::{
    impersonate::with_system_privileges, remove_mandatory_label, set_mandatory_label,
    spawn_system_process, get_object_label,
};
use std::path::Path;

/// 强制上锁（SYSTEM 权限）
///
/// # 用途
/// - 锁定系统级文件
/// - 应用 System 级标签
/// - 处理普通模式无法锁定的文件
///
/// # 实现
/// 直接在 SYSTEM 权限下调用 winsec::set_mandatory_label，
/// 绕过 core 层的权限检查，充分利用系统级权限
pub fn force_lock(
    path: &Path,
    opts: &LockOptions,
    effective_level: LabelLevel,
    user_sid: &str,
    logger: &NdjsonWriter,
) -> Result<LockResult> {
    with_system_privileges(|| {
        let ctx = OperationContext::new(path, user_sid, logger);
        let before = get_object_label(&ctx.path_str).ok();

        // 直接调用 winsec 层 API，不经过 core 层检查
        let result = set_mandatory_label(&ctx.path_str, effective_level);

        match result {
            Ok(_) => {
                let after = get_object_label(&ctx.path_str).ok();
                ctx.log_and_track(
                    opts.mode,
                    effective_level,
                    before.as_ref().map(|s| s.sddl.clone()),
                    after.as_ref().map(|s| s.sddl.clone()),
                    "success_elevated",
                    vec!["使用 SYSTEM 权限执行".to_string()],
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
                    "error_elevated",
                    vec![format!("{:?}", e), "SYSTEM 权限下仍然失败".to_string()],
                );
                Err(e)
            }
        }
    })
}

/// 强制解锁（SYSTEM 权限）
///
/// # 用途
/// - 解锁被 SYSTEM 级保护的文件
/// - 解锁权限损坏的文件
/// - 修复无法正常解锁的对象
pub fn force_unlock(path: &Path, user_sid: &str, logger: &NdjsonWriter) -> Result<LockResult> {
    with_system_privileges(|| {
        let ctx = OperationContext::new(path, user_sid, logger);
        let before = get_object_label(&ctx.path_str).ok();

        // 直接调用 winsec 层 API
        let result = remove_mandatory_label(&ctx.path_str);

        match result {
            Ok(_) => {
                ctx.log_and_track(
                    amberlock_types::ProtectMode::ReadOnly,
                    LabelLevel::Medium,
                    before.as_ref().map(|s| s.sddl.clone()),
                    None,
                    "unlocked_elevated",
                    vec!["使用 SYSTEM 权限执行".to_string()],
                );
                Ok(LockResult::Success)
            }
            Err(e) => {
                ctx.log_and_track(
                    amberlock_types::ProtectMode::ReadOnly,
                    LabelLevel::Medium,
                    before.as_ref().map(|s| s.sddl.clone()),
                    None,
                    "error_elevated",
                    vec![format!("{:?}", e), "SYSTEM 权限下仍然失败".to_string()],
                );
                Err(e)
            }
        }
    })
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
///
/// # 安全警告
/// 该操作会创建具有完整系统权限的进程，应谨慎使用
pub fn spawn_maintenance_shell() -> Result<u32> {
    let cmd = r#"cmd.exe /k title AmberLock 维护 Shell (SYSTEM) && echo. && echo *** SYSTEM 权限维护模式 *** && echo. && echo 当前权限: SYSTEM && echo 请谨慎操作！ && echo."#;
    spawn_system_process(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    fn check_elevated() -> bool {
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows::Win32::Security::TOKEN_QUERY;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use std::mem::zeroed;

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation: TOKEN_ELEVATION = zeroed();
            let mut return_length = 0u32;

            if GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            )
                .is_err()
            {
                CloseHandle(token).ok();
                return false;
            }

            CloseHandle(token).ok();
            elevation.TokenIsElevated != 0
        }
    }

    #[test]
    #[ignore] // 需要管理员权限
    fn test_force_lock() {
        if !check_elevated() {
            println!("⚠️ 跳过测试：需要管理员权限");
            return;
        }

        let temp_dir = TempDir::new().expect("创建临时目录失败");
        let test_file = temp_dir.path().join("test_force.txt");
        File::create(&test_file).expect("创建测试文件失败");

        let logger = NdjsonWriter::open_append(temp_dir.path().join("test.log"))
            .expect("创建日志失败");

        let user_sid = amberlock_winsec::read_user_sid().unwrap_or_default();
        let opts = LockOptions::default();

        match force_lock(&test_file, &opts, LabelLevel::System, &user_sid, &logger) {
            Ok(result) => println!("✅ 强制上锁成功: {:?}", result),
            Err(e) => println!("❌ 强制上锁失败: {:?}", e),
        }
    }

    #[test]
    #[ignore] // 需要管理员权限
    fn test_force_unlock() {
        if !check_elevated() {
            println!("⚠️ 跳过测试：需要管理员权限");
            return;
        }

        let temp_dir = TempDir::new().expect("创建临时目录失败");
        let test_file = temp_dir.path().join("test_force_unlock.txt");
        File::create(&test_file).expect("创建测试文件失败");

        let logger = NdjsonWriter::open_append(temp_dir.path().join("test.log"))
            .expect("创建日志失败");

        let user_sid = amberlock_winsec::read_user_sid().unwrap_or_default();

        // 先上锁
        let opts = LockOptions::default();
        let _ = force_lock(&test_file, &opts, LabelLevel::High, &user_sid, &logger);

        // 然后解锁
        match force_unlock(&test_file, &user_sid, &logger) {
            Ok(result) => println!("✅ 强制解锁成功: {:?}", result),
            Err(e) => println!("❌ 强制解锁失败: {:?}", e),
        }
    }
}