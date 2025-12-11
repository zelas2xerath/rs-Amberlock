//! 令牌窃取提权模块

use amberlock_types::{AmberlockError, Result};
use std::mem::{size_of, zeroed};
use windows::{
    Win32::Foundation::{CloseHandle, HANDLE, LUID},
    Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, ImpersonateLoggedOnUser, LUID_AND_ATTRIBUTES,
        LookupPrivilegeValueW, RevertToSelf, SE_PRIVILEGE_ENABLED, SecurityImpersonation,
        SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
        TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrimary, TokenSessionId,
    },
    Win32::System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        RemoteDesktop::WTSGetActiveConsoleSessionId,
        Threading::{
            CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
            NORMAL_PRIORITY_CLASS, OpenProcess, OpenProcessToken, PROCESS_INFORMATION,
            PROCESS_QUERY_INFORMATION, STARTUPINFOW,
        },
    },
    core::{PCWSTR, PWSTR},
};

/// SYSTEM 进程候选列表（按优先级排序）
///
/// 这些进程通常以 SYSTEM 权限运行，且令牌较容易访问
/// 参考：C 代码中的 SYSTEM_PROCESS_CANDIDATES
const SYSTEM_PROCESS_CANDIDATES: &[&str] = &[
    "winlogon.exe", // Windows 登录进程
    "lsass.exe",    // 本地安全授权子系统
    "services.exe", // 服务控制管理器
    "csrss.exe",    // 客户端/服务器运行时子系统
    "wininit.exe",  // Windows 启动进程
];

/// 进程枚举回调类型
/// 参考：C 代码中的 PKKLL_M_PROCESS_CALLBACK
type ProcessCallback = fn(&ProcessInfo) -> Result<()>;

/// 进程信息结构体，用于枚举回调
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
    ///
    /// # 实现步骤（参考 C kkll_m_process_enum 和 kkll_m_process_systoken_callback）
    /// 1. 获取当前活动控制台会话ID
    /// 2. 遍历候选进程，查找 SYSTEM 进程
    /// 3. 复制进程的主令牌
    /// 4. 修改令牌会话ID
    pub fn from_system_process() -> Result<Self> {
        unsafe {
            enable_privilege_by_name("SeDebugPrivilege").ok();

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
    /// # 注意
    /// 创建的进程将以 SYSTEM 权限运行，但绑定到当前用户桌面
    /// 参考：C kkll_m_process_create
    /// 优化：添加了进程信息清理
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

    /// 模拟线程令牌（临时提升为 SYSTEM 权限）
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

/// 从指定进程窃取令牌
///
/// # 参数
/// - `process_name`: 目标进程名称
/// - `session_id`: 目标会话ID
///
/// # 返回
/// - `Ok(HANDLE)`: 复制后的令牌句柄
/// - `Err`: 操作失败
///
/// # 实现步骤（参考 C steal_token_from_process 和 kkll_m_process_token）
/// 1. 打开目标进程
/// 2. 打开进程令牌
/// 3. 复制令牌（Primary 类型）
/// 4. 启用 SeTcbPrivilege
/// 5. 修改令牌会话ID
/// 优化：使用 HandleGuard 自动清理
fn steal_token_from_process(process_name: &str, session_id: u32) -> Result<HANDLE> {
    unsafe {
        let pid = get_pid_by_name(process_name)?;
        let mut h_token = HANDLE::default();
        // 打开进程（参考 C OpenProcess）
        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?;
        let _process_guard = HandleGuard(h_process);
        // 打开进程令牌（参考 C OpenProcessToken）
        OpenProcessToken(
            h_process,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
            &mut h_token,
        )?;
        let _token_guard = HandleGuard(h_token);

        // 复制令牌（参考 C DuplicateTokenEx）
        let mut h_dup_token = HANDLE::default();
        DuplicateTokenEx(
            h_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut h_dup_token,
        )?;

        //// 启用 SeTcbPrivilege（参考 C enable_privilege）
        enable_privilege_by_name_on_token(h_dup_token, "SeTcbPrivilege")?;

        // 修改会话ID（参考 C set_token_session_id）
        set_token_session_id(h_dup_token, session_id)?;

        Ok(h_dup_token)
    }
}

/// 在特定令牌上启用特权
///
/// # 参数
/// - `token`: 令牌句柄
/// - `privilege_name`: 特权名称（如 "SeTcbPrivilege"）
///
/// # 返回
/// - `Ok(())`: 启用成功
/// - `Err`: API 调用失败
/// 参考：C enable_privilege 和 kkll_m_process_fullprivileges
/// 优化：使用更安全的字符串处理
fn enable_privilege_by_name_on_token(token: HANDLE, privilege_name: &str) -> Result<()> {
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
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let mut previous: TOKEN_PRIVILEGES = zeroed();
        let mut return_length: u32 = 0;
        Ok(AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            size_of::<TOKEN_PRIVILEGES>() as u32,
            Some(&mut previous),
            Some(&mut return_length),
        )?)
    }
}

// 添加在当前进程令牌上启用特权的便捷函数
fn enable_privilege_by_name(privilege_name: &str) -> Result<()> {
    unsafe {
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows::Win32::Security::TOKEN_ADJUST_PRIVILEGES;

        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;
        let _guard = HandleGuard(token);

        enable_privilege_by_name_on_token(token, privilege_name)
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
/// 参考：C set_token_session_id
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

/// 获取进程ID通过名称（辅助函数）
///
/// # 参数
/// - `name`: 进程名称
///
/// # 返回
/// - `Ok(u32)`: 进程ID
/// - `Err`: 未找到进程
/// 参考：C PsGetProcessImageFileName 和进程枚举逻辑
/// 实现：使用 Toolhelp32Snapshot 枚举进程
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
                msg: "Process32FirstW failed".to_string(),
            });
        }

        loop {
            let proc_name = String::from_utf16_lossy(
                &entry.szExeFile[..entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len())],
            );
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
            msg: format!("Process {} not found", name),
        })
    }
}

/// 进程枚举函数
///
/// # 参数
/// - `callback`: 每个进程的回调函数
///
/// # 返回
/// - `Ok(())`: 枚举成功
/// - `Err`: 枚举失败
/// 参考：C kkll_m_process_enum
/// 实现：使用 Toolhelp32Snapshot 枚举所有进程，并为每个进程打开令牌（如果可能）
fn enumerate_processes(callback: ProcessCallback) -> Result<()> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let _snapshot_guard = HandleGuard(snapshot);

        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        // 修复7: 检查第一次调用是否成功
        if Process32FirstW(snapshot, &mut entry).is_err() {
            return Err(AmberlockError::Win32 {
                code: 0,
                msg: "Process32FirstW failed".to_string(),
            });
        }

        loop {
            let null_pos = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let proc_name = String::from_utf16_lossy(&entry.szExeFile[..null_pos]);

            // 修复8: 使用 match 更清晰地处理错误
            let h_process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, entry.th32ProcessID) {
                Ok(h) => h,
                Err(_) => {
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                    continue;
                }
            };

            let mut h_token = HANDLE::default();
            let token_result = OpenProcessToken(h_process, TOKEN_QUERY, &mut h_token);

            let info = ProcessInfo {
                pid: entry.th32ProcessID,
                name: proc_name,
                token: if token_result.is_ok() { h_token } else { HANDLE::default() },
            };

            callback(&info)?;

            if !h_process.is_invalid() {
                CloseHandle(h_process)?;
            }
            if !h_token.is_invalid() {
                CloseHandle(h_token)?;
            }

            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }

        Ok(())
    }
}

/// RAII 句柄守卫
/// 参考：C HandleGuard
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
/// 参考：C with_system_privileges
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

    // 修复10: 添加权限检查辅助函数
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
    fn test_impersonation_context_creation() {
        if !check_elevated() {
            println!("跳过测试：需要管理员权限");
            return;
        }

        match ImpersonationContext::from_system_process() {
            Ok(ctx) => {
                println!("成功创建 ImpersonationContext");
                println!("会话ID: {}", ctx.session_id);
            }
            Err(e) => {
                println!("创建失败: {:?}", e);
                println!("即使有管理员权限也失败，请检查系统环境");
            }
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
            Ok(pid) => {
                println!("成功创建 SYSTEM 进程: PID={}", pid);
            }
            Err(e) => {
                println!("创建失败: {:?}", e);
                panic!("即使有管理员权限也失败，请检查系统环境");
            }
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_with_system_privileges() {
        if !check_elevated() {
            println!("跳过测试：需要管理员权限");
            return;
        }

        let result = with_system_privileges(|| {
            println!("当前线程已提升为 SYSTEM");
            Ok(())
        });

        match result {
            Ok(_) => println!("✅ 提权操作成功"),
            Err(e) => {
                println!("提权失败: {:?}", e);
                panic!("即使有管理员权限也失败，请检查系统环境");
            }
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_get_pid_by_name() {
        match get_pid_by_name("explorer.exe") {
            Ok(pid) => println!("找到进程 PID: {}", pid),
            Err(e) => println!("错误: {:?}", e),
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_enumerate_processes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNT: AtomicUsize = AtomicUsize::new(0);

        fn callback(info: &ProcessInfo) -> Result<()> {
            let count = COUNT.fetch_add(1, Ordering::Relaxed);
            if count < 5 {
                println!("PID: {}, Name: {}", info.pid, info.name);
            }
            Ok(())
        }

        match enumerate_processes(callback) {
            Ok(_) => {
                let total = COUNT.load(Ordering::Relaxed);
                println!("枚举成功，共 {} 个进程", total);
            }
            Err(e) => println!("错误: {:?}", e),
        }
    }
}
