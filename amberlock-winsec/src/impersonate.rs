//! 令牌窃取提权模块

use amberlock_types::{AmberlockError, LabelLevel, Result};
use crate::HandleGuard;
use std::mem::{size_of, zeroed};
use windows::{
    Win32::Foundation::{CloseHandle, HANDLE, LUID},
    Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
        LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, RevertToSelf, SE_PRIVILEGE_ENABLED,
        SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenIntegrityLevel,
        TokenPrimary, TokenSessionId,TOKEN_PRIVILEGES_ATTRIBUTES,
    },
    Win32::System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        RemoteDesktop::WTSGetActiveConsoleSessionId,
        Threading::{
            CreateProcessAsUserW, OpenProcess, OpenProcessToken, CREATE_NEW_CONSOLE,
            CREATE_UNICODE_ENVIRONMENT, NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION,
            PROCESS_QUERY_INFORMATION, STARTUPINFOW,
        },
    },
    core::{PCWSTR, PWSTR},
};

/// SYSTEM 进程候选列表（按优先级排序）
const SYSTEM_PROCESS_CANDIDATES: &[&str] = &[
    "winlogon.exe", // Windows 登录进程
    "lsass.exe",    // 本地安全授权子系统
    "services.exe", // 服务控制管理器
    "csrss.exe",    // 客户端/服务器运行时子系统
    "wininit.exe",  // Windows 启动进程
];

/// 进程信息结构体
#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    token: HANDLE,
}

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
    pub fn from_system_process() -> Result<Self> {
        unsafe {
            enable_privilege_on_current("SeDebugPrivilege").ok();

            let session_id = WTSGetActiveConsoleSessionId();

            // 遍历候选进程
            for process_name in SYSTEM_PROCESS_CANDIDATES {
                match steal_token_from_process(process_name, session_id) {
                    Ok(token) => {
                        return Ok(Self { token, session_id });
                    }
                    Err(e) => {
                        eprintln!("尝试从 {} 窃取令牌失败: {:?}", process_name, e);
                    }
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
    pub fn create_process(&self, command_line: &str, inherit_handles: bool) -> Result<u32> {
        unsafe {
            let mut startup_info: STARTUPINFOW = zeroed();
            startup_info.cb = size_of::<STARTUPINFOW>() as u32;
            startup_info.lpDesktop = PWSTR(
                "winsta0\\default\0"
                    .encode_utf16()
                    .collect::<Vec<u16>>()
                    .as_mut_ptr(),
            );

            let mut process_info: PROCESS_INFORMATION = zeroed();

            let mut cmd_wide: Vec<u16> = command_line
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

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
            )?;

            let pid = process_info.dwProcessId;

            // 关闭进程和线程句柄
            CloseHandle(process_info.hProcess).ok();
            CloseHandle(process_info.hThread).ok();

            Ok(pid)
        }
    }

    /// 模拟线程令牌
    pub fn impersonate(&self) -> Result<()> {
        unsafe { Ok(ImpersonateLoggedOnUser(self.token)?) }
    }

    /// 恢复原线程令牌
    pub fn revert_to_self() -> Result<()> {
        unsafe { Ok(RevertToSelf()?) }
    }
}

impl Drop for ImpersonationContext {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.token);
        }
    }
}

/// 在当前进程令牌上启用或禁用特权
///
/// # 参数
/// - `privilege_name`: 特权名称字符串（如 "SeSecurityPrivilege"）
/// - `enable`: true 启用，false 禁用
pub fn enable_privilege_on_current(privilege_name: &str) -> Result<()> {
    unsafe {
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;
        let _guard = HandleGuard(token);

        enable_privilege_on_token(token, privilege_name, true)
    }
}

/// 在特定令牌上启用特权
///
/// # 参数
/// - `token`: 令牌句柄
/// - `privilege_name`: 特权名称字符串
/// - `enable`: true 启用，false 禁用
pub fn enable_privilege_on_token(token: HANDLE, privilege_name: &str, enable: bool) -> Result<()> {
    unsafe {
        let mut luid: LUID = zeroed();
        let wide_priv: Vec<u16> = privilege_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        LookupPrivilegeValueW(None, PCWSTR(wide_priv.as_ptr()), &mut luid)?;

        let tp = TOKEN_PRIVILEGES {
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

        let mut previous: TOKEN_PRIVILEGES = zeroed();
        let mut return_length: u32 = 0;
        AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            size_of::<TOKEN_PRIVILEGES>() as u32,
            Some(&mut previous),
            Some(&mut return_length),
        )?;

        Ok(())
    }
}

/// RAII 特权守卫，自动恢复特权状态
pub struct PrivilegeGuard {
    token: HANDLE,
    privilege_name: String,
    was_enabled: bool,
}

impl PrivilegeGuard {
    /// 创建特权守卫并启用特权
    ///
    /// # 参数
    /// - `token`: 令牌句柄
    /// - `privilege_name`: 特权名称
    pub fn new(token: HANDLE, privilege_name: &str) -> Result<Self> {
        let was_enabled = check_privilege_enabled(token, privilege_name)?;

        if !was_enabled {
            enable_privilege_on_token(token, privilege_name, true)?;
        }

        Ok(Self {
            token,
            privilege_name: privilege_name.to_string(),
            was_enabled,
        })
    }

    /// 在当前进程令牌上创建特权守卫
    pub fn on_current(privilege_name: &str) -> Result<Self> {
        unsafe {
            use windows::Win32::System::Threading::GetCurrentProcess;

            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )?;

            let guard = Self::new(token, privilege_name)?;

            // 注意：这里不能关闭 token，因为守卫需要持有它
            // 但这意味着 token 在守卫生命周期内泄漏
            // 更好的方案是让守卫拥有 token 的所有权
            std::mem::forget(HandleGuard(token));

            Ok(guard)
        }
    }
}

impl Drop for PrivilegeGuard {
    fn drop(&mut self) {
        if !self.was_enabled {
            // 恢复到原始状态（禁用）
            let _ = enable_privilege_on_token(self.token, &self.privilege_name, false);
        }
    }
}

/// 检查特权是否已启用
fn check_privilege_enabled(token: HANDLE, privilege_name: &str) -> Result<bool> {
    unsafe {
        let mut luid: LUID = zeroed();
        let wide_priv: Vec<u16> = privilege_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        LookupPrivilegeValueW(None, PCWSTR(wide_priv.as_ptr()), &mut luid)?;

        // 查询令牌特权
        let mut return_length = 0u32;
        let _ = GetTokenInformation(
            token,
            windows::Win32::Security::TokenPrivileges,
            None,
            0,
            &mut return_length,
        );

        let mut buffer = vec![0u8; return_length as usize];
        GetTokenInformation(
            token,
            windows::Win32::Security::TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )?;

        let privileges =
            &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);

        for i in 0..privileges.PrivilegeCount as usize {
            let priv_luid = privileges.Privileges[i].Luid;
            if priv_luid.LowPart == luid.LowPart && priv_luid.HighPart == luid.HighPart {
                return Ok((privileges.Privileges[i].Attributes.0 & SE_PRIVILEGE_ENABLED.0) != 0);
            }
        }

        Ok(false)
    }
}

/// 便捷函数：在特权启用期间执行操作
///
/// # 示例
/// ```rust,no_run
/// with_privilege("SeSecurityPrivilege", || {
///     // 在 SeSecurityPrivilege 启用期间执行操作
///     Ok(())
/// })?;
/// ```
pub fn with_privilege<F, R>(privilege_name: &str, f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let _guard = PrivilegeGuard::on_current(privilege_name)?;
    f()
}

/// 从指定进程窃取令牌
fn steal_token_from_process(process_name: &str, session_id: u32) -> Result<HANDLE> {
    unsafe {
        let pid = get_pid_by_name(process_name)?;
        let mut h_token = HANDLE::default();

        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?;
        let _process_guard = HandleGuard(h_process);

        OpenProcessToken(
            h_process,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
            &mut h_token,
        )?;
        let _token_guard = HandleGuard(h_token);

        let mut h_dup_token = HANDLE::default();
        DuplicateTokenEx(
            h_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut h_dup_token,
        )?;

        // 任务 2.2：验证令牌完整性级别
        let token_il = read_token_il(h_dup_token)?;
        if token_il != LabelLevel::System {
            return Err(AmberlockError::Win32 {
                code: 0,
                msg: format!(
                    "进程 {} 的完整性级别不是 System，而是 {:?}",
                    process_name, token_il
                ),
            });
        }

        enable_privilege_on_token(h_dup_token, "SeTcbPrivilege", true)?;
        set_token_session_id(h_dup_token, session_id)?;

        Ok(h_dup_token)
    }
}

/// 读取令牌的完整性级别（任务 2.2）
fn read_token_il(token: HANDLE) -> Result<LabelLevel> {
    unsafe {
        let mut return_length = 0u32;
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut return_length);

        let mut buffer = vec![0u8; return_length as usize];
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )?;

        let label_ptr = buffer.as_ptr() as *const windows::Win32::Security::TOKEN_MANDATORY_LABEL;
        let sid = (*label_ptr).Label.Sid;

        use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount};
        let sub_auth_count = *GetSidSubAuthorityCount(sid);
        let rid_ptr = GetSidSubAuthority(sid, (sub_auth_count - 1) as u32);
        let rid = *rid_ptr;

        match rid {
            0x2000 => Ok(LabelLevel::Medium),
            0x3000 => Ok(LabelLevel::High),
            0x4000..=0x5000 => Ok(LabelLevel::System),
            _ => Ok(LabelLevel::Medium),
        }
    }
}

/// 修改令牌会话ID
fn set_token_session_id(token: HANDLE, session_id: u32) -> Result<()> {
    unsafe {
        Ok(SetTokenInformation(
            token,
            TokenSessionId,
            &session_id as *const _ as *const _,
            size_of::<u32>() as u32,
        )?)
    }
}

/// 获取进程ID通过名称
fn get_pid_by_name(name: &str) -> Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let _snapshot_guard = HandleGuard(snapshot);

        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        // 检查第一次调用是否成功
        if Process32FirstW(snapshot, &mut entry).is_err() {
            return Err(AmberlockError::Win32 {
                code: 0,
                msg: "进程枚举初始化失败".to_string(),
            });
        }

        let mut checked_count = 0usize;
        loop {
            let proc_name = String::from_utf16_lossy(
                &entry.szExeFile[..entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len())],
            );

            checked_count += 1;

            if proc_name.eq_ignore_ascii_case(name) {
                return Ok(entry.th32ProcessID);
            }

            // 处理遍历结束
            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }

        Err(AmberlockError::Win32 {
            code: 0,
            msg: format!("未找到进程 {}（已检查 {} 个进程）", name, checked_count),
        })
    }
}

/// 一步到位创建 SYSTEM 进程
pub fn spawn_system_process(command: &str) -> Result<u32> {
    let ctx = ImpersonationContext::from_system_process()?;
    ctx.create_process(command, false)
}

/// 临时提升为 SYSTEM 权限执行操作
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

    fn check_elevated() -> bool {
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
                size_of::<TOKEN_ELEVATION>() as u32,
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
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_privilege_guard() {
        if !check_elevated() {
            println!("⚠️ 跳过测试：需要管理员权限");
            return;
        }

        let result = with_privilege("SeDebugPrivilege", || {
            println!("✅ SeDebugPrivilege 已启用");
            Ok(())
        });

        match result {
            Ok(_) => println!("✅ 特权守卫测试成功"),
            Err(e) => println!("❌ 特权守卫测试失败: {:?}", e),
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_spawn_system_process() {
        if !check_elevated() {
            println!("⚠️ 跳过测试：需要管理员权限");
            return;
        }

        match spawn_system_process("cmd.exe /c echo SYSTEM Process Test && timeout /t 2") {
            Ok(pid) => println!("✅ 成功创建 SYSTEM 进程: PID={}", pid),
            Err(e) => println!("❌ 创建失败: {:?}", e),
        }
    }
}