//! 对话框模块
//!
//! 提供用户交互对话框，包括确认、警告等

use crate::MainWindow;

/// 卷根锁定确认对话框
///
/// # 参数
/// - `app`: 主窗口引用
///
/// # 返回
/// - `true`: 用户确认继续
/// - `false`: 用户取消操作
///
/// # 警告信息
/// 对卷根（如 C:\）进行锁定可能影响：
/// - 系统更新和维护
/// - 应用程序安装
/// - 系统文件访问
pub fn confirm_volume_root_lock(_app: &MainWindow) -> bool {
    // 注意：由于 Slint 目前没有原生对话框 API，
    // 这里使用简化实现。生产环境应使用 native-dialog 或自定义 Slint 对话框。

    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{
            IDYES, MB_ICONWARNING, MB_YESNO, MessageBoxW,
        };
        use windows::core::PCWSTR;

        let title = "⚠️ 卷根保护警告\0";
        let message = "您正在尝试锁定卷根（如 C:\\），这可能导致：\n\n\
                       ❌ 系统更新失败\n\
                       ❌ 应用程序无法安装\n\
                       ❌ 系统服务异常\n\n\
                       建议仅使用【只读模式 + NW 策略】。\n\n\
                       确定要继续吗？\0";

        unsafe {
            let title_wide: Vec<u16> = title.encode_utf16().collect();
            let message_wide: Vec<u16> = message.encode_utf16().collect();

            let result = MessageBoxW(
                None,
                PCWSTR(message_wide.as_ptr()),
                PCWSTR(title_wide.as_ptr()),
                MB_YESNO | MB_ICONWARNING,
            );

            result == IDYES
        }
    }

    #[cfg(not(windows))]
    {
        // 非 Windows 平台：始终返回 false（不支持 MIC）
        eprintln!("⚠️ 卷根锁定仅支持 Windows 平台");
        false
    }
}

/// 显示错误对话框
///
/// # 参数
/// - `title`: 对话框标题
/// - `message`: 错误消息
pub fn show_error_dialog(title: &str, message: &str) {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        use windows::core::PCWSTR;

        unsafe {
            let title_wide: Vec<u16> = format!("{}\0", title).encode_utf16().collect();
            let message_wide: Vec<u16> = format!("{}\0", message).encode_utf16().collect();

            MessageBoxW(
                None,
                PCWSTR(message_wide.as_ptr()),
                PCWSTR(title_wide.as_ptr()),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("❌ {}: {}", title, message);
    }
}

/// 显示信息对话框
///
/// # 参数
/// - `title`: 对话框标题
/// - `message`: 信息内容
pub fn show_info_dialog(title: &str, message: &str) {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
        use windows::core::PCWSTR;

        unsafe {
            let title_wide: Vec<u16> = format!("{}\0", title).encode_utf16().collect();
            let message_wide: Vec<u16> = format!("{}\0", message).encode_utf16().collect();

            MessageBoxW(
                None,
                PCWSTR(message_wide.as_ptr()),
                PCWSTR(title_wide.as_ptr()),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }

    #[cfg(not(windows))]
    {
        println!("ℹ️ {}: {}", title, message);
    }
}

/// 显示警告对话框
///
/// # 参数
/// - `title`: 对话框标题
/// - `message`: 警告内容
///
/// # 返回
/// - `true`: 用户点击"确定"
/// - `false`: 用户点击"取消"
pub fn show_warning_dialog(title: &str, message: &str) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{
            IDOK, MB_ICONWARNING, MB_OKCANCEL, MessageBoxW,
        };
        use windows::core::PCWSTR;

        unsafe {
            let title_wide: Vec<u16> = format!("{}\0", title).encode_utf16().collect();
            let message_wide: Vec<u16> = format!("{}\0", message).encode_utf16().collect();

            let result = MessageBoxW(
                None,
                PCWSTR(message_wide.as_ptr()),
                PCWSTR(title_wide.as_ptr()),
                MB_OKCANCEL | MB_ICONWARNING,
            );

            result == IDOK
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("⚠️ {}: {}", title, message);
        false
    }
}

/// 首次运行欢迎对话框
pub fn show_first_run_welcome() {
    let message = "欢迎使用 AmberLock！\n\n\
                   这是您首次运行本程序。系统已自动创建密码保险库，\n\
                   默认密码为：amberlock\n\n\
                   ⚠️ 请尽快修改密码以确保安全！\n\n\
                   提示：\n\
                   • 锁定操作需要管理员权限\n\
                   • 封印模式将尝试 System 级保护\n\
                   • 请谨慎操作卷根（C:\\ 等）";

    show_info_dialog("首次运行", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // 需要手动测试（会弹出对话框）
    fn test_show_info_dialog() {
        show_info_dialog("测试", "这是一个测试对话框");
    }
}
