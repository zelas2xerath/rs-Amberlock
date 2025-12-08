//! 密码保险库管理模块
//!
//! 提供保险库的初始化、验证和管理功能

use anyhow::{Context, Result};
use std::path::Path;

/// 保险库状态
#[derive(Debug, Clone, PartialEq)]
pub enum VaultStatus {
    /// 保险库不存在
    NotExists,
    /// 保险库已创建
    Exists,
    /// 保险库损坏
    Corrupted,
}

/// 检查保险库状态
///
/// # 参数
/// - `vault_path`: 保险库文件路径
///
/// # 返回
/// 保险库当前状态
pub fn check_vault_status<P: AsRef<Path>>(vault_path: P) -> VaultStatus {
    let path = vault_path.as_ref();

    if !path.exists() {
        return VaultStatus::NotExists;
    }

    // 尝试读取文件验证格式
    match std::fs::read(path) {
        Ok(blob) => {
            // 尝试加载验证结构完整性
            match amberlock_auth::load_vault(&blob) {
                Ok(_) => VaultStatus::Exists,
                Err(_) => VaultStatus::Corrupted,
            }
        }
        Err(_) => VaultStatus::Corrupted,
    }
}

/// 创建新的密码保险库
///
/// # 参数
/// - `vault_path`: 保险库文件路径
/// - `password`: 主密码
///
/// # 返回
/// - `Ok(())`: 创建成功
/// - `Err`: 文件写入失败或密码哈希失败
///
/// # 注意
/// - 如果文件已存在，会被覆盖
/// - 密码不应包含前导/尾随空格
pub fn create_vault<P: AsRef<Path>>(vault_path: P, password: &str) -> Result<()> {
    let path = vault_path.as_ref();

    // 确保父目录存在
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("无法创建保险库目录")?;
    }

    // 创建保险库 blob
    let vault_blob = amberlock_auth::create_vault(password).context("创建保险库失败")?;

    // 写入文件
    std::fs::write(path, &vault_blob).context("写入保险库文件失败")?;

    Ok(())
}

/// 验证保险库密码
///
/// # 参数
/// - `vault_path`: 保险库文件路径
/// - `password`: 待验证的密码
///
/// # 返回
/// - `Ok(true)`: 密码正确
/// - `Ok(false)`: 密码错误
/// - `Err`: 保险库文件不存在或损坏
pub fn verify_vault_password<P: AsRef<Path>>(vault_path: P, password: &str) -> Result<bool> {
    let vault_blob = std::fs::read(vault_path.as_ref()).context("无法读取保险库文件")?;

    amberlock_auth::verify_password(&vault_blob, password).context("密码验证失败")
}

/// 更改保险库密码
///
/// # 参数
/// - `vault_path`: 保险库文件路径
/// - `old_password`: 旧密码
/// - `new_password`: 新密码
///
/// # 返回
/// - `Ok(())`: 修改成功
/// - `Err`: 旧密码错误或文件操作失败
pub fn change_vault_password<P: AsRef<Path>>(
    vault_path: P,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    let path = vault_path.as_ref();

    // 验证旧密码
    if !verify_vault_password(path, old_password)? {
        anyhow::bail!("旧密码错误");
    }

    // 创建新保险库
    create_vault(path, new_password).context("创建新保险库失败")?;

    Ok(())
}

/// 首次启动初始化：自动创建保险库
///
/// # 参数
/// - `vault_path`: 保险库文件路径
/// - `default_password`: 默认密码（建议引导用户设置）
///
/// # 返回
/// - `Ok(true)`: 创建了新保险库
/// - `Ok(false)`: 保险库已存在
/// - `Err`: 创建失败
pub fn initialize_vault_if_needed<P: AsRef<Path>>(
    vault_path: P,
    default_password: &str,
) -> Result<bool> {
    let status = check_vault_status(&vault_path);

    match status {
        VaultStatus::NotExists => {
            create_vault(&vault_path, default_password)?;
            Ok(true)
        }
        VaultStatus::Exists => Ok(false),
        VaultStatus::Corrupted => {
            anyhow::bail!("保险库文件已损坏，请删除后重新创建");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_vault_lifecycle() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // 初始状态：不存在
        std::fs::remove_file(path).ok();
        assert_eq!(check_vault_status(path), VaultStatus::NotExists);

        // 创建保险库
        create_vault(path, "test_password_123").unwrap();
        assert_eq!(check_vault_status(path), VaultStatus::Exists);

        // 验证密码
        assert!(verify_vault_password(path, "test_password_123").unwrap());
        assert!(!verify_vault_password(path, "wrong_password").unwrap());

        // 更改密码
        change_vault_password(path, "test_password_123", "new_password_456").unwrap();
        assert!(verify_vault_password(path, "new_password_456").unwrap());
        assert!(!verify_vault_password(path, "test_password_123").unwrap());
    }

    #[test]
    fn test_initialize_vault_if_needed() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        std::fs::remove_file(path).ok();

        // 首次初始化：创建新保险库
        let created = initialize_vault_if_needed(path, "default_pass").unwrap();
        assert!(created);

        // 再次初始化：不创建
        let created_again = initialize_vault_if_needed(path, "default_pass").unwrap();
        assert!(!created_again);
    }
}
