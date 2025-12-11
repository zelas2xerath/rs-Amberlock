//! SDDL 字符串构造与解析

use amberlock_types::{AmberlockError, LabelLevel, Result};
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SE_FILE_OBJECT, SetNamedSecurityInfoW,
    },
    Security::{LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SACL_SECURITY_INFORMATION},
    System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
};
use windows::core::PWSTR;

/// 将 LabelLevel 映射到 SDDL 标记
///
/// # 映射规则
/// - Medium → "ME" (S-1-16-0x2000)
/// - High → "HI" (S-1-16-0x3000)
/// - System → "SI" (S-1-16-0x4000)
pub fn level_to_sddl_token(level: LabelLevel) -> &'static str {
    match level {
        LabelLevel::Medium => "ME",
        LabelLevel::High => "HI",
        LabelLevel::System => "SI",
    }
}

/// 构造 Mandatory Label 的 SDDL 段
///
/// # 参数
/// - `level`: 目标完整性级别
///
/// # 返回
/// SDDL 字符串，格式固定为 "S:(ML;;NW;;;级别)"
///
/// # 注意
/// 任务 3.2：移除所有策略参数，固定使用 "NW" 策略
pub fn build_ml_sddl(level: LabelLevel) -> String {
    let level_token = level_to_sddl_token(level);
    format!("S:(ML;;NW;;;{})", level_token)
}

/// 从对象读取 SACL 中的 Mandatory Label
///
/// # 参数
/// - `path`: 文件/目录路径
///
/// # 返回
/// - `Ok((Some(level), sddl))`: 存在 ML，返回级别和完整 SDDL
/// - `Ok((None, sddl))`: 无 ML，仅返回 SDDL
/// - `Err`: API 调用失败
pub fn read_ml_from_object(path: &str) -> Result<(Option<LabelLevel>, String)> {
    unsafe {
        let wide_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

        let mut sd_ptr: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        let mut sacl_ptr = std::ptr::null_mut();

        GetNamedSecurityInfoW(
            PWSTR(wide_path.as_ptr() as *mut _),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(&mut sacl_ptr),
            &mut sd_ptr,
        )
            .ok()
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("获取对象 {} 的安全信息失败: {}", path, e),
            })?;

        // 转换安全描述符为 SDDL 字符串
        let mut sddl_ptr = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd_ptr,
            SECURITY_DESCRIPTOR_REVISION,
            SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut sddl_ptr,
            None,
        )
            .map_err(|e| AmberlockError::Win32 {
                code: e.code().0 as u32,
                msg: format!("安全描述符转换为 SDDL 失败: {}", e),
            })?;

        let sddl_string = sddl_ptr.to_string().map_err(|e| AmberlockError::Win32 {
            code: 0,
            msg: format!("SDDL 包含无效的 UTF-16: {}", e),
        })?;

        // 释放 Windows 分配的内存
        LocalFree(Some(HLOCAL(sd_ptr.0)));
        LocalFree(Some(HLOCAL(sddl_ptr.0 as *mut _)));

        // 解析 SDDL 提取 ML 信息
        let level = parse_ml_from_sddl(&sddl_string);

        Ok((level, sddl_string))
    }
}

/// 清除对象中的 Mandatory Label
///
/// # 参数
/// - `path`: 文件/目录路径
///
/// # 返回
/// - `Ok(())`: 清除成功或对象本无 ML
/// - `Err`: API 调用失败
pub fn clear_ml_on_object(path: &str) -> Result<()> {
    unsafe {
        let wide_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

        // 构造空 SACL 的 SDDL
        let empty_sacl_sddl = "S:";
        let wide_sddl: Vec<u16> = empty_sacl_sddl.encode_utf16().chain(Some(0)).collect();

        // 转换 SDDL 为安全描述符
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

        // 应用空 SACL 到对象
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

        // 释放内存
        LocalFree(Some(HLOCAL(sd_ptr.0)));

        Ok(())
    }
}

/// 从 SDDL 字符串解析 ML 信息
///
/// # 参数
/// - `sddl`: 完整的 SDDL 字符串
///
/// # 返回
/// - `Some(level)`: 解析成功
/// - `None`: 无 ML 或解析失败
///
fn parse_ml_from_sddl(sddl: &str) -> Option<LabelLevel> {
    // 简化实现：查找 ML ACE 标记
    if let Some(ml_start) = sddl.find("(ML;;") {
        let ml_section = &sddl[ml_start..];

        // 首先尝试匹配符号名称
        if ml_section.contains("SI") {
            return Some(LabelLevel::System);
        } else if ml_section.contains("HI") {
            return Some(LabelLevel::High);
        } else if ml_section.contains("ME") {
            return Some(LabelLevel::Medium);
        }

        // 尝试匹配完整 SID（S-1-16-xxxx）
        if ml_section.contains("S-1-16-16384") || ml_section.contains("S-1-16-4000") {
            return Some(LabelLevel::System);
        } else if ml_section.contains("S-1-16-12288") || ml_section.contains("S-1-16-3000") {
            return Some(LabelLevel::High);
        } else if ml_section.contains("S-1-16-8192") || ml_section.contains("S-1-16-2000") {
            return Some(LabelLevel::Medium);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ml_sddl() {
        assert_eq!(build_ml_sddl(LabelLevel::Medium), "S:(ML;;NW;;;ME)");
        assert_eq!(build_ml_sddl(LabelLevel::High), "S:(ML;;NW;;;HI)");
        assert_eq!(build_ml_sddl(LabelLevel::System), "S:(ML;;NW;;;SI)");
        println!("✅ SDDL 构造测试通过");
    }

    #[test]
    fn test_parse_ml_from_sddl() {
        assert_eq!(
            parse_ml_from_sddl("S:(ML;;NW;;;ME)"),
            Some(LabelLevel::Medium)
        );
        assert_eq!(
            parse_ml_from_sddl("S:(ML;;NW;;;HI)"),
            Some(LabelLevel::High)
        );
        assert_eq!(
            parse_ml_from_sddl("S:(ML;;NW;;;SI)"),
            Some(LabelLevel::System)
        );

        // 测试完整 SID 格式
        assert_eq!(
            parse_ml_from_sddl("S:(ML;;NW;;;S-1-16-12288)"),
            Some(LabelLevel::High)
        );

        println!("✅ SDDL 解析测试通过");
    }

    #[test]
    fn test_level_to_sddl_token() {
        assert_eq!(level_to_sddl_token(LabelLevel::Medium), "ME");
        assert_eq!(level_to_sddl_token(LabelLevel::High), "HI");
        assert_eq!(level_to_sddl_token(LabelLevel::System), "SI");
        println!("✅ 级别转换测试通过");
    }
}