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
    pub caller_il: LabelLevel,
    pub has_se_security: bool,
    pub has_se_relabel: bool,
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
            Privileges: [TOKEN_PRIVILEGES_ATTRIBUTES {
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

pub fn enable_privilege(p: Privilege, enable: bool) -> Result<bool>;

/// 读取当前进程令牌的完整性级别（Medium/High/System 映射）
pub fn read_process_il() -> Result<LabelLevel>;

/// 读取当前进程用户 SID（用于日志）
pub fn read_user_sid() -> Result<String>;

/// 启动前自检（IL + 特权）
pub fn probe_capability() -> Result<CapabilityProbe>;
