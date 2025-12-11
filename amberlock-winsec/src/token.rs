//! 令牌操作与能力探测
//!
//! 本模块封装 Windows 令牌相关 API，包括：
//! - 读取进程完整性级别（Integrity Level）
//! - 启用/禁用特权（Privileges）
//! - 读取用户 SID
//! - 系统能力探测与缓存

use amberlock_types::{AmberlockError, CapabilityProbe, LabelLevel, Result};
use crate::HandleGuard;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::{
    Foundation::{LocalFree, HANDLE, HLOCAL},
    Security::Authorization::ConvertSidToStringSidW,
    Security::{GetTokenInformation, TokenIntegrityLevel, TokenUser},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};


/// 全局能力探测缓存
static CAPABILITY_CACHE: Lazy<Mutex<Option<CapabilityProbe>>> = Lazy::new(|| Mutex::new(None));

/// 读取当前进程的完整性级别
pub fn read_process_il() -> Result<LabelLevel> {
    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).map_err(|e| {
            AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("打开进程令牌失败: {}", e),
            }
        })?;

        let _guard = HandleGuard(token_handle);

        let mut return_length = 0u32;
        let _ = GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            None,
            0,
            &mut return_length,
        );

        // 分配缓冲区并再次查询
        let mut buffer = vec![0u8; return_length as usize];
        GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("获取令牌完整性级别失败: {}", e),
            })?;

        // 解析 TOKEN_MANDATORY_LABEL 结构
        // 结构布局：Label (SID_AND_ATTRIBUTES) -> Sid (PSID) -> SubAuthority[...]
        let label_ptr = buffer.as_ptr() as *const windows::Win32::Security::TOKEN_MANDATORY_LABEL;
        let sid = (*label_ptr).Label.Sid;

        // 获取 SubAuthority 数组（最后一个元素是 RID）
        use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount};
        let sub_auth_count = *GetSidSubAuthorityCount(sid);
        let rid_ptr = GetSidSubAuthority(sid, (sub_auth_count - 1) as u32);
        let rid = *rid_ptr;

        // 根据 RID 映射到完整性级别
        // 标准映射：0x1000=Low, 0x2000=Medium, 0x3000=High, 0x4000=System
        match rid {
            0x2000 => Ok(LabelLevel::Medium),
            0x3000 => Ok(LabelLevel::High),
            0x4000..=0x5000 => Ok(LabelLevel::System),
            _ => Ok(LabelLevel::Medium),
        }
    }
}

/// 读取当前用户的 SID 字符串
pub fn read_user_sid() -> Result<String> {
    unsafe {
        // 打开当前进程令牌
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).map_err(|e| {
            AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("打开进程令牌失败: {}", e),
            }
        })?;

        let _guard = HandleGuard(token_handle);

        // 查询用户信息
        let mut return_length = 0u32;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut return_length);

        let mut buffer = vec![0u8; return_length as usize];
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("获取令牌用户信息失败: {}", e),
            })?;

        // 解析 TOKEN_USER 结构
        let token_user_ptr = buffer.as_ptr() as *const windows::Win32::Security::TOKEN_USER;
        let sid = (*token_user_ptr).User.Sid;

        // 转换 SID 为字符串
        let mut sid_string = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_string).map_err(|e| AmberlockError::Win32 {
            code: e.code().0 as u32,
            msg: format!("转换 SID 为字符串失败: {}", e),
        })?;

        // 转换为 Rust String
        let result = sid_string.to_string().map_err(|e| AmberlockError::Win32 {
            code: 0,
            msg: format!("SID 包含无效的 UTF-16: {}", e),
        })?;

        // 释放 Windows 分配的字符串
        LocalFree(Some(HLOCAL(sid_string.0 as *mut core::ffi::c_void)));

        Ok(result)
    }
}

/// 系统能力探测（带缓存）
///
/// # 返回
/// 包含当前进程能力的完整报告
///
/// # 缓存机制
/// 首次调用时执行完整探测，后续调用直接返回缓存结果
pub fn probe_capability() -> Result<CapabilityProbe> {
    // 尝试从缓存获取
    {
        let cache = CAPABILITY_CACHE.lock().unwrap();
        if let Some(ref probe) = *cache {
            return Ok(probe.clone());
        }
    }

    // 缓存未命中，执行探测
    let probe = execute_capability_probe()?;

    // 存入缓存
    {
        let mut cache = CAPABILITY_CACHE.lock().unwrap();
        *cache = Some(probe.clone());
    }

    Ok(probe)
}

/// 清空能力探测缓存（用于测试或需要重新探测的场景）
pub fn clear_capability_cache() {
    let mut cache = CAPABILITY_CACHE.lock().unwrap();
    *cache = None;
}

/// 执行实际的能力探测
fn execute_capability_probe() -> Result<CapabilityProbe> {
    use crate::impersonate::enable_privilege_on_current;

    let caller_il = read_process_il()?;

    // 尝试启用 SeSecurityPrivilege
    let has_se_security = enable_privilege_on_current("SeSecurityPrivilege").is_ok();

    // 尝试启用 SeRelabelPrivilege
    let has_se_relabel = enable_privilege_on_current("SeRelabelPrivilege").is_ok();

    let user_sid = read_user_sid().unwrap_or_default();

    Ok(CapabilityProbe {
        caller_il,
        has_se_security,
        has_se_relabel,
        user_sid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_process_il() {
        match read_process_il() {
            Ok(level) => println!("✅ 当前进程完整性级别: {:?}", level),
            Err(e) => println!("❌ 读取失败: {:?}", e),
        }
    }

    #[test]
    fn test_read_user_sid() {
        match read_user_sid() {
            Ok(sid) => println!("✅ 当前用户 SID: {}", sid),
            Err(e) => println!("❌ 读取失败: {:?}", e),
        }
    }

    #[test]
    fn test_capability_probe() {
        match probe_capability() {
            Ok(probe) => {
                println!("✅ 能力探测成功:");
                println!("  完整性级别: {:?}", probe.caller_il);
                println!("  SeSecurityPrivilege: {}", probe.has_se_security);
                println!("  SeRelabelPrivilege: {}", probe.has_se_relabel);
                println!("  用户 SID: {}", probe.user_sid);
            }
            Err(e) => println!("❌ 探测失败: {:?}", e),
        }
    }

    #[test]
    fn test_capability_cache() {
        clear_capability_cache();

        let probe1 = probe_capability().expect("首次探测失败");
        let probe2 = probe_capability().expect("第二次探测失败");

        assert_eq!(probe1.caller_il, probe2.caller_il);
        assert_eq!(probe1.user_sid, probe2.user_sid);

        println!("✅ 能力探测缓存测试成功");
    }
}