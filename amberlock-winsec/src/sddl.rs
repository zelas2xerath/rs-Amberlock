//! SDDL 字符串构造与解析
//!
//! 本模块负责：
//! - 将 LabelLevel 映射到 SDDL 标记（ME/HI/SI）
//! - 构造 Mandatory Label 的 SDDL 段（如 "S:(ML;;NW;;;HI)"）
//! - 从对象读取 SACL 中的 ML
//! - 清除对象的 ML

use amberlock_types::{AmberlockError, LabelLevel, MandPolicy, Result};
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
/// - `policy`: 强制策略位（NW/NR/NX 组合）
///
/// # 返回
/// SDDL 字符串，格式如 "S:(ML;;NW;;;HI)"
///
/// # SDDL 格式说明
/// `S:(ML;;策略;;;级别)`
/// - S: SACL 开始标记
/// - ML: Mandatory Label ACE 类型
/// - ;;: 权限字段（ML 类型不使用）
/// - 策略: NW/NR/NX 组合（如 "NWNRNX"）
/// - ;;;: 保留字段
/// - 级别: ME/HI/SI
pub fn build_ml_sddl(level: LabelLevel, policy: MandPolicy) -> String {
    let level_token = level_to_sddl_token(level);

    // 构造策略字符串
    let mut policy_str = String::new();
    if policy.contains(MandPolicy::NW) {
        policy_str.push_str("NW");
    }
    if policy.contains(MandPolicy::NR) {
        policy_str.push_str("NR");
    }
    if policy.contains(MandPolicy::NX) {
        policy_str.push_str("NX");
    }

    // 如果策略为空，默认使用 NW
    if policy_str.is_empty() {
        policy_str = "NW".to_string();
    }

    format!("S:(ML;;{};;;{})", policy_str, level_token)
}

/// 从对象读取 SACL 中的 Mandatory Label
///
/// # 参数
/// - `path`: 文件/目录路径
///
/// # 返回
/// - `Ok((Some(level), Some(policy), sddl))`: 存在 ML，返回级别、策略和完整 SDDL
/// - `Ok((None, None, sddl))`: 无 ML，仅返回 SDDL
/// - `Err`: API 调用失败
pub fn read_ml_from_object(path: &str) -> Result<(Option<LabelLevel>, Option<MandPolicy>, String)> {
    unsafe {
        // 转换路径为宽字符
        let wide_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

        // 读取对象的 SACL
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
            msg: format!("GetNamedSecurityInfoW failed for {}: {}", path, e),
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
            msg: format!(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {}",
                e
            ),
        })?;

        let sddl_string = sddl_ptr.to_string().map_err(|e| AmberlockError::Win32 {
            code: 0,
            msg: format!("Invalid UTF-16 in SDDL: {}", e),
        })?;

        // 释放 Windows 分配的内存
        LocalFree(Some(HLOCAL(sd_ptr.0)));
        LocalFree(Some(HLOCAL(sddl_ptr.0 as *mut _)));

        // 解析 SDDL 提取 ML 信息
        let (level, policy) = parse_ml_from_sddl(&sddl_string);

        Ok((level, policy, sddl_string))
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
///
/// # 实现策略
/// 设置一个空的 SACL（不包含 ML ACE）
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
            msg: format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                e
            ),
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
            msg: format!("SetNamedSecurityInfoW failed for {}: {}", path, e),
        })?;

        // 释放内存
        LocalFree(Some(HLOCAL(sd_ptr.0)));

        Ok(())
    }
}

/// 内部函数：从 SDDL 字符串解析 ML 信息
///
/// # 参数
/// - `sddl`: 完整的 SDDL 字符串
///
/// # 返回
/// - `(Some(level), Some(policy))`: 解析成功
/// - `(None, None)`: 无 ML 或解析失败
///
/// # 解析逻辑
/// 查找 "S:(ML;;" 标记，提取策略和级别
fn parse_ml_from_sddl(sddl: &str) -> (Option<LabelLevel>, Option<MandPolicy>) {
    // 简化实现：查找 ML ACE 标记
    if let Some(ml_start) = sddl.find("(ML;;") {
        let ml_section = &sddl[ml_start..];

        // 提取策略（NW/NR/NX）
        let mut policy = MandPolicy::empty();
        if ml_section.contains("NW") {
            policy |= MandPolicy::NW;
        }
        if ml_section.contains("NR") {
            policy |= MandPolicy::NR;
        }
        if ml_section.contains("NX") {
            policy |= MandPolicy::NX;
        }

        // 提取级别（ME/HI/SI）
        let level = if ml_section.contains("ME") {
            Some(LabelLevel::Medium)
        } else if ml_section.contains("HI") {
            Some(LabelLevel::High)
        } else if ml_section.contains("SI") {
            Some(LabelLevel::System)
        } else {
            None
        };

        return (level, Some(policy));
    }

    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_to_sddl_token() {
        assert_eq!(level_to_sddl_token(LabelLevel::Medium), "ME");
        assert_eq!(level_to_sddl_token(LabelLevel::High), "HI");
        assert_eq!(level_to_sddl_token(LabelLevel::System), "SI");
    }

    #[test]
    fn test_build_ml_sddl() {
        let sddl = build_ml_sddl(LabelLevel::High, MandPolicy::NW);
        assert_eq!(sddl, "S:(ML;;NW;;;HI)");

        let sddl_complex = build_ml_sddl(
            LabelLevel::System,
            MandPolicy::NW | MandPolicy::NR | MandPolicy::NX,
        );
        assert_eq!(sddl_complex, "S:(ML;;NWNRNX;;;SI)");
    }

    #[test]
    fn test_parse_ml_from_sddl() {
        let sddl = "S:(ML;;NW;;;HI)";
        let (level, policy) = parse_ml_from_sddl(sddl);
        assert_eq!(level, Some(LabelLevel::High));
        assert_eq!(policy, Some(MandPolicy::NW));

        let empty_sddl = "D:(A;;FA;;;WD)";
        let (level2, policy2) = parse_ml_from_sddl(empty_sddl);
        assert_eq!(level2, None);
        assert_eq!(policy2, None);
    }
}
