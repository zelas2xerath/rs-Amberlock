//! 令牌窃取提权模块
//!
//! **警告：此模块包含高风险功能，仅用于合法系统管理和安全研究**
//!
//! 本模块实现 Windows 令牌窃取技术，通过以下步骤实现权限提升：
//! 1. 遍历系统进程，定位 SYSTEM 权限进程
//! 2. 复制 SYSTEM 进程的主令牌（Primary Token）
//! 3. 启用 SeTcbPrivilege 特权
//! 4. 修改令牌会话ID，绑定到当前用户会话
//! 5. 使用修改后的令牌创建 SYSTEM 进程
//!
//! # 安全警告
//! - 需要管理员权限运行
//! - 可能触发安全软件报警
//! - 仅在受控环境中使用
//! - 不得用于非法目的
//!
//! # 技术原理
//! Windows 系统中，每个进程拥有一个令牌（Token），标识其权限级别。
//! 通过复制 SYSTEM 令牌并修改其会话ID，可以创建绑定到当前用户桌面的 SYSTEM 进程。

use super::token::Privilege;
use amberlock_types::{ AmberlockError, Result };
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
    RevertToSelf, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ADJUST_SESSIONID, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
};
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, OpenProcess, OpenProcessToken, PROCESS_CREATE_PROCESS,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, NORMAL_PRIORITY_CLASS,
};

/// SYSTEM 进程候选列表（按优先级排序）
///
/// 这些进程通常以 SYSTEM 权限运行，且令牌较容易访问
const SYSTEM_PROCESS_CANDIDATES: &[&str] = &[
    "winlogon.exe",  // Windows 登录进程
    "lsass.exe",     // 本地安全授权子系统
    "services.exe",  // 服务控制管理器
    "csrss.exe",     // 客户端/服务器运行时子系统
    "wininit.exe",   // Windows 启动进程
];

/// 令牌窃取上下文
///
/// 封装令牌复制和进程创建所需的上下文信息
pub struct ImpersonationContext {
    /// 复制的 SYSTEM 令牌句柄
    token: HANDLE,
    /// 当前用户会话ID
    session_id: u32,
}

impl ImpersonationContext {
    /// 从 SYSTEM 进程创建令牌窃取上下文
    ///
    /// # 返回
    /// - `Ok(Self)`: 成功创建上下文
    /// - `Err`: 无法找到 SYSTEM 进程或令牌复制失败
    ///
    /// # 实现步骤
    /// 1. 获取当前活动控制台会话ID
    /// 2. 遍历候选进程，查找 SYSTEM 进程
    /// 3. 复制进程的主令牌
    /// 4. 修改令牌会话ID
    pub fn from_system_process() -> Result<Self> {
        unsafe {
            // 获取当前活动会话ID
            let session_id = WTSGetActiveConsoleSessionId();

            // 遍历候选进程
            for process_name in SYSTEM_PROCESS_CANDIDATES {
                if let Ok(token) = steal_token_from_process(process_name, session_id) {
                    return Ok(Self { token, session_id });
                }
            }

            Err(AmberlockError::Win32 {
                code: 0,
                msg: "无法找到可用的 SYSTEM 进程".to_string(),
            })
        }
    }

    /// 使用窃取的令牌创建新进程
    ///
    /// # 参数
    /// - `command_line`: 要执行的命令行（如 "cmd.exe"）
    /// - `inherit_handles`: 是否继承句柄
    ///
    /// # 返回
    /// - `Ok(u32)`: 新进程的 PID
    /// - `Err`: 进程创建失败
    ///
    /// # 注意
    /// 创建的进程将以 SYSTEM 权限运行，但绑定到当前用户桌面
    pub fn create_process(&self, command_line: &str, inherit_handles: bool) -> Result<u32> {
        unsafe {
            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = size_of::<STARTUPINFOW>() as u32;
            startup_info.lpDesktop = PWSTR(
                "winsta0\\default\0"
                    .encode_utf16()
                    .collect::<Vec<u16>>()
                    .as_mut_ptr(),
            );

            let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

            let mut cmd_wide: Vec<u16> = format!("{}\0", command_line).encode_utf16().collect();

            let flags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS;

            CreateProcessAsUserW(
                Option::from(self.token),
                None,
                Option::from(PWSTR(cmd_wide.as_mut_ptr())),
                None,
                None,
                inherit_handles,
                flags,
                None,
                None,
                &startup_info,
                &mut process_info,
            )
                .map_err(|e| AmberlockError::Win32 {
                    code: e.code().0 as u32,
                    msg: format!("CreateProcessAsUserW 失败: {}", e),
                })?;

            let pid = process_info.dwProcessId;

            // 关闭进程和线程句柄
            CloseHandle(process_info.hProcess).ok();
            CloseHandle(process_info.hThread).ok();

            Ok(pid)
        }
    }

    /// 模拟令牌（Impersonation）
    ///
    /// 使当前线程临时获得 SYSTEM 权限
    ///
    /// # 返回
    /// - `Ok(())`: 模拟成功
    /// - `Err`: API 调用失败
    ///
    /// # 注意
    /// 调用后需手动调用 `revert_to_self()` 恢复原始权限
    pub fn impersonate(&self) -> Result<()> {
        unsafe {
            ImpersonateLoggedOnUser(self.token).map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("ImpersonateLoggedOnUser 失败: {}", e),
            })
        }
    }

    /// 恢复原始线程令牌
    pub fn revert_to_self() -> Result<()> {
        unsafe {
            RevertToSelf().map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("RevertToSelf 失败: {}", e),
            })
        }
    }
}

impl Drop for ImpersonationContext {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.token);
        }
    }
}

/// 从指定进程名窃取令牌
///
/// # 参数
/// - `process_name`: 目标进程名（如 "winlogon.exe"）
/// - `session_id`: 目标会话ID
///
/// # 返回
/// - `Ok(HANDLE)`: 复制并修改后的令牌句柄
/// - `Err`: 进程未找到或令牌操作失败
fn steal_token_from_process(process_name: &str, session_id: u32) -> Result<HANDLE> {
    unsafe {
        // 查找进程PID
        let pid = find_process_by_name(process_name)?;

        // 打开进程
        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS,
            false,
            pid,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("OpenProcess 失败: {}", e),
            })?;

        let _guard = HandleGuard(process_handle);

        // 打开进程令牌
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            process_handle,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("OpenProcessToken 失败: {}", e),
            })?;

        let _token_guard = HandleGuard(token_handle);

        // 复制令牌为 Primary Token
        let mut duplicated_token = HANDLE::default();
        DuplicateTokenEx(
            token_handle,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicated_token,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("DuplicateTokenEx 失败: {}", e),
            })?;

        // 启用 SeTcbPrivilege（修改会话ID需要）
        enable_tcb_privilege(duplicated_token)?;

        // 修改令牌会话ID
        set_token_session_id(duplicated_token, session_id)?;

        Ok(duplicated_token)
    }
}

/// 查找进程PID（简化实现）
///
/// # 注意
/// 实际实现应遍历所有进程快照（使用 CreateToolhelp32Snapshot）
/// 这里假设通过其他方式已获取PID
fn find_process_by_name(process_name: &str) -> Result<u32> {
    // 简化实现：遍历常见PID范围
    // 生产环境应使用 CreateToolhelp32Snapshot + Process32First/Next
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| {
            AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("CreateToolhelp32Snapshot 失败: {}", e),
            }
        })?;

        let _guard = HandleGuard(HANDLE(snapshot.0));

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_lowercase();

                if name == process_name.to_lowercase() {
                    return Ok(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        Err(AmberlockError::Win32 {
            code: 0,
            msg: format!("未找到进程: {}", process_name),
        })
    }
}

/// 启用令牌的 SeTcbPrivilege
///
/// # 参数
/// - `token`: 令牌句柄
///
/// # 返回
/// - `Ok(())`: 启用成功
/// - `Err`: 特权不存在或启用失败
fn enable_tcb_privilege(token: HANDLE) -> Result<()> {
    unsafe {
        // 查找 SeTcbPrivilege 的 LUID
        let mut luid = LUID::default();
        let priv_name = "SeTcbPrivilege\0".encode_utf16().collect::<Vec<u16>>();

        windows::Win32::Security::LookupPrivilegeValueW(
            None,
            windows::core::PCWSTR(priv_name.as_ptr()),
            &mut luid,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("LookupPrivilegeValueW 失败: {}", e),
            })?;

        // 构造 TOKEN_PRIVILEGES
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // 调整令牌特权
        AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None).map_err(|e| {
            AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("AdjustTokenPrivileges 失败: {}", e),
            }
        })
    }
}

/// 修改令牌会话ID
///
/// # 参数
/// - `token`: 令牌句柄
/// - `session_id`: 目标会话ID
///
/// # 返回
/// - `Ok(())`: 修改成功
/// - `Err`: API 调用失败
fn set_token_session_id(token: HANDLE, session_id: u32) -> Result<()> {
    unsafe {
        SetTokenInformation(
            token,
            TokenSessionId,
            &session_id as *const _ as *const _,
            size_of::<u32>() as u32,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("SetTokenInformation(SessionId) 失败: {}", e),
            })
    }
}

/// RAII 句柄守卫
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// 高级API：一步到位创建 SYSTEM 进程
///
/// # 参数
/// - `command`: 要执行的命令（如 "cmd.exe" 或自定义程序路径）
///
/// # 返回
/// - `Ok(u32)`: 新进程的 PID
/// - `Err`: 创建失败
///
/// # 示例
/// ```rust,no_run
/// // 启动 SYSTEM 权限的 cmd.exe
/// let pid = spawn_system_process("cmd.exe")?;
/// println!("已创建 SYSTEM 进程: PID={}", pid);
/// ```
pub fn spawn_system_process(command: &str) -> Result<u32> {
    let ctx = ImpersonationContext::from_system_process()?;
    ctx.create_process(command, false)
}

/// 临时提升为 SYSTEM 权限执行操作
///
/// # 参数
/// - `f`: 要在 SYSTEM 权限下执行的闭包
///
/// # 返回
/// 闭包的返回值
///
/// # 示例
/// ```rust,no_run
/// with_system_privileges(|| {
///     // 这里的代码以 SYSTEM 权限运行
///     println!("当前线程已提升为 SYSTEM");
///     // 执行需要高权限的操作
///     Ok(())
/// })?;
/// ```
pub fn with_system_privileges<F, R>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let ctx = ImpersonationContext::from_system_process()?;
    ctx.impersonate()?;

    let result = f();

    ImpersonationContext::revert_to_self()?;

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_impersonation_context_creation() {
        // 注意：此测试需要管理员权限运行
        match ImpersonationContext::from_system_process() {
            Ok(ctx) => {
                println!("✅ 成功创建 ImpersonationContext");
                println!("  会话ID: {}", ctx.session_id);
            }
            Err(e) => {
                println!("⚠️ 需要管理员权限: {:?}", e);
            }
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    #[ignore] // 需要手动测试，会创建新进程
    fn test_spawn_system_process() {
        match spawn_system_process("cmd.exe /c echo SYSTEM Process && pause") {
            Ok(pid) => {
                println!("✅ 成功创建 SYSTEM 进程: PID={}", pid);
            }
            Err(e) => {
                println!("❌ 创建失败: {:?}", e);
            }
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_with_system_privileges() {
        let result = with_system_privileges(|| {
            println!("✅ 当前线程已提升为 SYSTEM");
            Ok(())
        });

        match result {
            Ok(_) => println!("✅ 提权操作成功"),
            Err(e) => println!("⚠️ 需要管理员权限: {:?}", e),
        }
    }
}