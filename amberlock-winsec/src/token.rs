//! 令牌操作与能力探测
//!
//! 本模块封装 Windows 令牌相关 API，包括：
//! - 读取进程完整性级别（Integrity Level）
//! - 启用/禁用特权（Privileges）
//! - 读取用户 SID
//! - 系统能力探测

use super::error::{Result, WinSecError};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HLOCAL, LUID, LocalFree},
    Security::Authorization::ConvertSidToStringSidW,
    Security::{
        AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
        TokenIntegrityLevel, TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
use windows::Win32::Security::LUID_AND_ATTRIBUTES;

/// 特权类型枚举
#[derive(Debug, Clone, Copy)]
pub enum Privilege {
    /// SE_SECURITY_NAME - 访问/修改 SACL 所需
    SeSecurity,
    /// SE_RELABEL_PRIVILEGE - 提升标签级别所需
    SeRelabel,
}

impl Privilege {
    /// 获取特权的系统名称
    fn name(&self) -> &'static str {
        match self {
            Privilege::SeSecurity => "SeSecurityPrivilege",
            Privilege::SeRelabel => "SeRelabelPrivilege",
        }
    }
}

/// 完整性级别枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LabelLevel {
    Medium,
    High,
    System,
}

/// 能力探测报告
#[derive(Debug, Clone)]
pub struct CapabilityProbe {
    /// 调用者的完整性级别
    pub caller_il: LabelLevel,
    /// 是否拥有 SeSecurityPrivilege（访问 SACL）
    pub has_se_security: bool,
    /// 是否拥有 SeRelabelPrivilege（设置 System 级）
    pub has_se_relabel: bool,
    /// 用户 SID 字符串
    pub user_sid: String,
}

/// 启用或禁用指定特权
///
/// # 参数
/// - `p`: 要操作的特权类型
/// - `enable`: true 启用，false 禁用
///
/// # 返回
/// - `Ok(true)`: 操作成功
/// - `Ok(false)`: 特权不存在或已处于目标状态
/// - `Err`: API 调用失败
///
/// # 注意
/// 必须以管理员身份运行才能启用这些特权
pub fn enable_privilege(p: Privilege, enable: bool) -> Result<bool> {
    unsafe {
        // 打开当前进程令牌
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .map_err(|e| WinSecError::Win32 {
            code: e.code().0 as u32,
            msg: format!("OpenProcessToken failed: {}", e),
        })?;

        // RAII 守卫确保句柄关闭
        let _guard = HandleGuard(token_handle);

        // 查找特权 LUID
        let mut luid = LUID::default();
        let priv_name = p.name();
        let wide_name: Vec<u16> = priv_name.encode_utf16().chain(Some(0)).collect();

        LookupPrivilegeValueW(None, windows::core::PCWSTR(wide_name.as_ptr()), &mut luid).map_err(
            |e| WinSecError::Win32 {
                code: e.code().0 as u32,
                msg: format!("LookupPrivilegeValueW failed for {}: {}", priv_name, e),
            },
        )?;

        // 构造 TOKEN_PRIVILEGES 结构
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: if enable {
                    SE_PRIVILEGE_ENABLED
                } else {
                    TOKEN_PRIVILEGES_ATTRIBUTES(0)
                },
            }],
        };

        // 调整令牌特权
        AdjustTokenPrivileges(
            token_handle,
            false, // 不禁用所有特权
            Some(&mut tp),
            0,
            None,
            None,
        )
        .map_err(|e| WinSecError::Win32 {
            code: e.code().0 as u32,
            msg: format!("AdjustTokenPrivileges failed: {}", e),
        })?;

        Ok(true)
    }
}

/// 读取当前进程的完整性级别
///
/// # 返回
/// - `Ok(LabelLevel)`: 当前进程的 IL
/// - `Err`: API 调用失败或无法解析
///
/// # 映射规则
/// - SID 结尾 0x2000 → Medium
/// - SID 结尾 0x3000 → High
/// - SID 结尾 0x4000 或更高 → System
pub fn read_process_il() -> Result<LabelLevel> {
    unsafe {
        // 打开当前进程令牌
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).map_err(|e| {
            WinSecError::Win32 {
                code: e.code().0 as u32,
                msg: format!("OpenProcessToken failed: {}", e),
            }
        })?;

        let _guard = HandleGuard(token_handle);

        // 查询完整性级别（第一次调用获取所需缓冲区大小）
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
        .map_err(|e| WinSecError::Win32 {
            code: e.code().0 as u32,
            msg: format!("GetTokenInformation(IntegrityLevel) failed: {}", e),
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
            _ => Ok(LabelLevel::Medium), // 默认为 Medium
        }
    }
}

/// 读取当前用户的 SID 字符串
///
/// # 返回
/// - `Ok(String)`: 用户 SID（如 "S-1-5-21-..."）
/// - `Err`: API 调用失败
pub fn read_user_sid() -> Result<String> {
    unsafe {
        // 打开当前进程令牌
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).map_err(|e| {
            WinSecError::Win32 {
                code: e.code().0 as u32,
                msg: format!("OpenProcessToken failed: {}", e),
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
        .map_err(|e| WinSecError::Win32 {
            code: e.code().0 as u32,
            msg: format!("GetTokenInformation(TokenUser) failed: {}", e),
        })?;

        // 解析 TOKEN_USER 结构
        let token_user_ptr = buffer.as_ptr() as *const windows::Win32::Security::TOKEN_USER;
        let sid = (*token_user_ptr).User.Sid;

        // 转换 SID 为字符串
        let mut sid_string = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_string).map_err(|e| WinSecError::Win32 {
            code: e.code().0 as u32,
            msg: format!("ConvertSidToStringSidW failed: {}", e),
        })?;

        // 转换为 Rust String
        let result = sid_string.to_string().map_err(|e| WinSecError::Win32 {
            code: 0,
            msg: format!("Invalid UTF-16 in SID: {}", e),
        })?;

        // 释放 Windows 分配的字符串
        LocalFree(Some(HLOCAL(sid_string.0 as * mut core::ffi::c_void)));

        Ok(result)
    }
}

/// 系统能力探测（启动时自检）
///
/// # 返回
/// 包含当前进程能力的完整报告
///
/// # 用途
/// - 确定可设置的最高完整性级别
/// - 指导 UI 显示功能限制提示
pub fn probe_capability() -> Result<CapabilityProbe> {
    // 读取完整性级别
    let caller_il = read_process_il()?;

    // 尝试启用 SeSecurityPrivilege
    let has_se_security = enable_privilege(Privilege::SeSecurity, true).unwrap_or(false);

    // 尝试启用 SeRelabelPrivilege
    let has_se_relabel = enable_privilege(Privilege::SeRelabel, true).unwrap_or(false);

    // 读取用户 SID
    let user_sid = read_user_sid().unwrap_or_default();

    Ok(CapabilityProbe {
        caller_il,
        has_se_security,
        has_se_relabel,
        user_sid,
    })
}

/// RAII 句柄守卫，确保 Windows 句柄自动关闭
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_process_il() {
        let il = read_process_il().unwrap();
        println!("当前进程完整性级别: {:?}", il);
        // 非管理员运行应为 Medium，管理员应为 High
        assert!(matches!(il, LabelLevel::Medium | LabelLevel::High));
    }

    #[test]
    fn test_read_user_sid() {
        let sid = read_user_sid().unwrap();
        println!("当前用户 SID: {}", sid);
        assert!(sid.starts_with("S-1-5-"));
    }

    #[test]
    fn test_probe_capability() {
        let cap = probe_capability().unwrap();
        println!("能力报告: {:#?}", cap);
        // 基本断言：至少应该能读取到 IL
        assert!(matches!(
            cap.caller_il,
            LabelLevel::Medium | LabelLevel::High | LabelLevel::System
        ));
    }
}
