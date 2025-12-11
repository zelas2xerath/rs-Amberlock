//! Mandatory Label 设置与移除

use crate::{
    sddl::{build_ml_sddl, clear_ml_on_object, read_ml_from_object},
    impersonate::with_privilege,
};
use amberlock_types::{AmberlockError, LabelLevel, Result};
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    },
    Security::{LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SACL_SECURITY_INFORMATION},
    System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
};
use windows::core::PWSTR;

/// SDDL 标签信息（读取结果）
#[derive(Debug, Clone)]
pub struct SddlLabel {
    /// 完整 SDDL 字符串
    pub sddl: String,
    /// 解析出的完整性级别
    pub level: LabelLevel,
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
/// 若期望 System 但无 SeRelabelPrivilege，降为 High
pub fn compute_effective_level(desired: LabelLevel, can_set_system: bool) -> LabelLevel {
    match desired {
        LabelLevel::System if !can_set_system => LabelLevel::High,
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
pub fn get_object_label(path: &str) -> Result<SddlLabel> {
    let (level_opt, sddl) = read_ml_from_object(path)?;

    Ok(SddlLabel {
        sddl,
        level: level_opt.unwrap_or(LabelLevel::Medium),
    })
}

/// 设置对象的 Mandatory Label
///
/// # 参数
/// - `path`: 文件/目录路径
/// - `level`: 目标完整性级别
///
/// # 返回
/// - `Ok(())`: 设置成功
/// - `Err`: 权限不足或 API 调用失败
///
pub fn set_mandatory_label(path: &str, level: LabelLevel) -> Result<()> {
    unsafe {
        // 1. 启用必需特权
        enable_privilege(Privilege::SeSecurity, true).map_err(|_| {
            AmberlockError::PrivilegeMissing("SeSecurityPrivilege required to set SACL")
        })?;

        // 若设置 System 级，尝试启用 SeRelabelPrivilege
        if level == LabelLevel::System {
            let _ = enable_privilege(Privilege::SeRelabel, true);
        }

        unsafe {
            let ml_sddl = build_ml_sddl(level);
            let wide_sddl: Vec<u16> = ml_sddl.encode_utf16().chain(Some(0)).collect();

            let mut sd_ptr: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PWSTR(wide_sddl.as_ptr() as *mut _),
                SECURITY_DESCRIPTOR_REVISION,
                &mut sd_ptr,
                None,
            )
                .map_err(|e| AmberlockError::Win32 {
                    code: e.code().0 as u32,
                    msg: format!("SDDL 转换为安全描述符失败: {}", e),
                })?;

            let wide_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

            SetNamedSecurityInfoW(
                PWSTR(wide_path.as_ptr() as *mut _),
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                None,
                None,
                None,
                Some(sd_ptr.0 as *const _),
            )
                .ok()
                .map_err(|e| AmberlockError::Win32 {
                    code: e.code().0 as u32,
                    msg: format!("设置对象 {} 的安全信息失败: {}", path, e),
                })?;

        // 5. 释放内存
        LocalFree(Some(HLOCAL(sd_ptr.0)));

            Ok(())
        }
    })
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
        AmberlockError::PrivilegeMissing("SeSecurityPrivilege required to modify SACL")
    })?;

    // 清除 ML
    clear_ml_on_object(path)?;

    // 恢复特权
    let _ = enable_privilege(Privilege::SeSecurity, false);

    Ok(())
}

/// 导出 level_to_sddl_token 供外部使用（如日志格式化）
pub use super::sddl::level_to_sddl_token;

