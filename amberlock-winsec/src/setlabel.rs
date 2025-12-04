//! Mandatory Label 设置与移除
//!
//! 本模块是 winsec 的核心，实现：
//! - 设置对象的强制完整性标签
//! - 移除对象的标签
//! - 读取对象当前标签
//! - 自动降级逻辑（System → High）

use super::error::{Result, WinSecError};
use super::sddl::{build_ml_sddl, clear_ml_on_object, read_ml_from_object};
use super::token::{enable_privilege, Privilege};
use windows::core::PWSTR;
use windows::Win32::{
    Foundation::{LocalFree, HLOCAL},
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    },
    Security::{LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SACL_SECURITY_INFORMATION},
    System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
};
use windows::core::PWSTR;

/// 完整性级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LabelLevel {
    Medium,
    High,
    System,
}

bitflags! {
    /// 强制策略位
    ///
    /// # 策略说明
    /// - NW (No-Write-Up): 禁止低完整性主体写入高完整性对象（**默认且可靠**）
    /// - NR (No-Read-Up): 禁止低完整性主体读取高完整性对象（**对文件不保证**）
    /// - NX (No-Execute-Up): 禁止低完整性主体执行高完整性代码（**对文件不保证**）
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct MandPolicy: u32 {
        const NW = 0x1;
        const NR = 0x2;
        const NX = 0x4;
    }
}

/// SDDL 标签信息（读取结果）
#[derive(Debug, Clone)]
pub struct SddlLabel {
    /// 完整 SDDL 字符串
    pub sddl: String,
    /// 解析出的完整性级别
    pub level: LabelLevel,
    /// 解析出的强制策略
    pub policy: MandPolicy,
}

/// 计算有效完整性级别（自动降级）
///
/// # 参数
/// - `desired`: 用户期望的级别
/// - `can_set_system`: 是否拥有 SeRelabelPrivilege
///
/// # 返回
/// 实际可设置的级别
///
/// # 降级规则
/// - 若期望 System 但无 SeRelabelPrivilege → 降为 High
/// - 其他情况保持原级别
pub fn compute_effective_level(desired: LabelLevel, can_set_system: bool) -> LabelLevel {
    match desired {
        LabelLevel::System if !can_set_system => {
            // 无权限设置 System，降级为 High
            LabelLevel::High
        }
        _ => desired,
    }
}

/// 获取对象当前的 Mandatory Label
///
/// # 参数
/// - `path`: 文件/目录路径
///
/// # 返回
/// - `Ok(SddlLabel)`: 包含完整标签信息
/// - `Err`: API 调用失败
///
/// # 注意
/// 若对象无 ML，level 和 policy 为默认值（Medium + NW）
pub fn get_object_label(path: &str) -> Result<SddlLabel> {
    let (level_opt, policy_opt, sddl) = read_ml_from_object(path)?;

    Ok(SddlLabel {
        sddl,
        level: level_opt.unwrap_or(LabelLevel::Medium),
        policy: policy_opt.unwrap_or(MandPolicy::NW),
    })
}

/// 设置对象的 Mandatory Label
///
/// # 参数
/// - `path`: 文件/目录路径
/// - `level`: 目标完整性级别
/// - `policy`: 强制策略（通常仅 NW）
///
/// # 返回
/// - `Ok(())`: 设置成功
/// - `Err`: 权限不足或 API 调用失败
///
/// # 实现步骤
/// 1. 启用 SeSecurityPrivilege（必需）
/// 2. 若 level=System，尝试启用 SeRelabelPrivilege
/// 3. 构造 SDDL 并转换为安全描述符
/// 4. 调用 SetNamedSecurityInfoW 应用
/// 5. 恢复特权状态
///
/// # 注意
/// - 必须以管理员身份运行
/// - 设置 System 级需要 SeRelabelPrivilege
pub fn set_mandatory_label(path: &str, level: LabelLevel, policy: MandPolicy) -> Result<()> {
    unsafe {
        // 1. 启用必需特权
        enable_privilege(Privilege::SeSecurity, true).map_err(|_| {
            WinSecError::PrivilegeMissing("SeSecurityPrivilege required to set SACL")
        })?;

        // 若设置 System 级，尝试启用 SeRelabelPrivilege
        if level == LabelLevel::System {
            let _ = enable_privilege(Privilege::SeRelabel, true);
        }

        // 2. 构造 SDDL
        let ml_sddl = build_ml_sddl(level, policy);
        let wide_sddl: Vec<u16> = ml_sddl.encode_utf16().chain(Some(0)).collect();

        // 3. 转换 SDDL 为安全描述符
        let mut sd_ptr: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PWSTR(wide_sddl.as_ptr() as *mut _),
            SECURITY_DESCRIPTOR_REVISION,
            &mut sd_ptr,
            None,
        )
        .map_err(|e| WinSecError::Win32 {
            code: e.code().0 as u32,
            msg: format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                e
            ),
        })?;

        // 4. 应用到对象
        let wide_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

        SetNamedSecurityInfoW(
            PWSTR(wide_path.as_ptr() as *mut _),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(sd_ptr.0 as *const _),
        ).ok()
        .map_err(|e| WinSecError::Win32 {
            code: e.code().0 as u32,
            msg: format!("SetNamedSecurityInfoW failed for {}: {}", path, e),
        })?;

        // 5. 释放内存
        LocalFree(Some(HLOCAL(sd_ptr.0)));

        // 6. 恢复特权（可选，程序退出时自动清理）
        let _ = enable_privilege(Privilege::SeSecurity, false);
        if level == LabelLevel::System {
            let _ = enable_privilege(Privilege::SeRelabel, false);
        }

        Ok(())
    }
}

/// 移除对象的 Mandatory Label
///
/// # 参数
/// - `path`: 文件/目录路径
///
/// # 返回
/// - `Ok(())`: 移除成功
/// - `Err`: 权限不足或 API 调用失败
///
/// # 注意
/// 移除后对象恢复为默认的隐式 Medium 级别
pub fn remove_mandatory_label(path: &str) -> Result<()> {
    // 启用特权
    enable_privilege(Privilege::SeSecurity, true).map_err(|_| {
        WinSecError::PrivilegeMissing("SeSecurityPrivilege required to modify SACL")
    })?;

    // 清除 ML
    clear_ml_on_object(path)?;

    // 恢复特权
    let _ = enable_privilege(Privilege::SeSecurity, false);

    Ok(())
}

/// 导出 level_to_sddl_token 供外部使用（如日志格式化）
pub use super::sddl::level_to_sddl_token;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_compute_effective_level() {
        assert_eq!(
            compute_effective_level(LabelLevel::System, false),
            LabelLevel::High
        );
        assert_eq!(
            compute_effective_level(LabelLevel::System, true),
            LabelLevel::System
        );
        assert_eq!(
            compute_effective_level(LabelLevel::High, false),
            LabelLevel::High
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn test_set_and_get_label() {
        // 创建临时文件
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"test").unwrap();

        let path = test_file.to_string_lossy();

        // 设置 High + NW
        let result = set_mandatory_label(&path, LabelLevel::High, MandPolicy::NW);
        if result.is_err() {
            println!("警告：需要管理员权限才能运行此测试");
            return;
        }

        // 读取验证
        let label = get_object_label(&path).unwrap();
        assert_eq!(label.level, LabelLevel::High);
        assert!(label.policy.contains(MandPolicy::NW));

        // 移除标签
        remove_mandatory_label(&path).unwrap();
    }

    #[test]
    fn test_policy_bitflags() {
        let policy = MandPolicy::NW | MandPolicy::NR;
        assert!(policy.contains(MandPolicy::NW));
        assert!(policy.contains(MandPolicy::NR));
        assert!(!policy.contains(MandPolicy::NX));
    }
}
