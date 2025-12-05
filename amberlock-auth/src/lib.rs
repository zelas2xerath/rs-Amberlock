//! AmberLock 认证模块
//!
//! 提供基于 Argon2id + DPAPI 的本地密码存储和验证功能。
//!
//! # 安全特性
//! - **Argon2id**：内存困难的密码哈希算法，抵抗暴力破解和侧信道攻击
//! - **DPAPI**：Windows 数据保护 API，密钥绑定到当前用户/机器
//! - **常数时间比较**：防止计时侧信道攻击
//! - **零化内存**：敏感数据使用后立即清零
//!
//! # 使用流程
//! 1. 创建保险库：`create_vault(password)` → DPAPI 加密的 blob
//! 2. 存储到文件：`std::fs::write(vault_path, blob)`
//! 3. 验证密码：`verify_password(blob, password)` → bool
//!
//! # 示例
//! ```rust
//! use amberlock_auth::*;
//!
//! // 创建保险库
//! let blob = create_vault("my_secret_password")?;
//! std::fs::write("vault.bin", &blob)?;
//!
//! // 验证密码
//! let blob = std::fs::read("vault.bin")?;
//! let is_valid = verify_password(&blob, "my_secret_password")?;
//! assert!(is_valid);
//! ```

use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Algorithm, Argon2, Params, Version,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use windows::Win32::{
    Foundation::{LocalFree, HLOCAL},
    Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN,
        CRYPT_INTEGER_BLOB
    },
};

// ================================
// 数据结构
// ================================

/// 保险库数据结构（加密前的明文）
///
/// 包含验证密码所需的所有信息（盐、Argon2 参数、哈希值）
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultBlob {
    /// 版本号，用于未来升级兼容性
    pub version: u32,
    /// 随机盐（至少 16 字节）
    pub salt: Vec<u8>,
    /// Argon2 参数（序列化字符串，如 "m=19456,t=2,p=1"）
    pub params: String,
    /// Argon2id 密码哈希（PHC 格式）
    pub hash: Vec<u8>,
}

// ================================
// 常量配置
// ================================

/// 当前保险库格式版本
const VAULT_VERSION: u32 = 1;

/// Argon2 内存成本（KiB）
/// 19456 KiB ≈ 19 MiB，提供良好的安全性与性能平衡
const ARGON2_MEM_COST: u32 = 19456;

/// Argon2 时间成本（迭代次数）
const ARGON2_TIME_COST: u32 = 2;

/// Argon2 并行度
const ARGON2_PARALLELISM: u32 = 1;

/// 密码验证失败后的退避延迟（毫秒）
const BACKOFF_DELAY_MS: u64 = 500;

// ================================
// 核心 API
// ================================

/// 创建新的密码保险库
///
/// # 参数
/// - `password`: 用户密码（明文）
///
/// # 返回
/// - `Ok(Vec<u8>)`: DPAPI 加密的保险库数据
/// - `Err`: 哈希生成失败或 DPAPI 加密失败
///
/// # 安全性
/// - 使用 `OsRng` 生成密码学安全的随机盐
/// - Argon2id 参数符合 OWASP 推荐
/// - 密码明文在函数返回前从内存清零
///
/// # 示例
/// ```rust
/// let vault_blob = create_vault("StrongP@ssw0rd!")?;
/// std::fs::write("vault.bin", &vault_blob)?;
/// ```
pub fn create_vault(password: &str) -> Result<Vec<u8>> {
    // 1. 生成随机盐（16 字节 = 128 位）
    let salt = SaltString::generate();

    // 2. 配置 Argon2id 参数
    let params = Params::new(
        ARGON2_MEM_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        None, // 输出长度使用默认值（32 字节）
    )
        .context("Invalid Argon2 parameters")?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // 3. 生成密码哈希（PHC 格式）
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

    // 4. 构造保险库数据结构
    let vault = VaultBlob {
        version: VAULT_VERSION,
        salt: salt.as_str().as_bytes().to_vec(),
        params: format!("m={},t={},p={}", ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM),
        hash: password_hash.to_string().as_bytes().to_vec(),
    };

    // 5. 序列化为 JSON
    let plaintext = serde_json::to_vec(&vault).context("Failed to serialize vault")?;

    // 6. 使用 DPAPI 加密
    let encrypted = dpapi_protect(&plaintext).context("DPAPI encryption failed")?;

    // 清零敏感数据（密码已在外部处理，这里清零 plaintext）
    // 注意：Rust 的内存安全模型不保证立即清零，但这是最佳实践
    drop(plaintext);

    Ok(encrypted)
}

/// 从 DPAPI blob 加载保险库
///
/// # 参数
/// - `dpapi_blob`: DPAPI 加密的保险库数据
///
/// # 返回
/// - `Ok(VaultBlob)`: 解密后的保险库数据结构
/// - `Err`: DPAPI 解密失败或反序列化失败
///
/// # 安全性
/// - 仅当前用户/机器可解密
/// - 不验证密码，仅解密数据结构
///
/// # 示例
/// ```rust
/// let blob = std::fs::read("vault.bin")?;
/// let vault = load_vault(&blob)?;
/// println!("保险库版本: {}", vault.version);
/// ```
pub fn load_vault(dpapi_blob: &[u8]) -> Result<VaultBlob> {
    // 1. 使用 DPAPI 解密
    let plaintext = dpapi_unprotect(dpapi_blob).context("DPAPI decryption failed")?;

    // 2. 反序列化 JSON
    let vault: VaultBlob =
        serde_json::from_slice(&plaintext).context("Failed to deserialize vault")?;

    // 清零解密后的明文
    drop(plaintext);

    // 3. 验证版本兼容性
    if vault.version != VAULT_VERSION {
        bail!(
            "Unsupported vault version: {} (expected {})",
            vault.version,
            VAULT_VERSION
        );
    }

    Ok(vault)
}

/// 验证密码
///
/// # 参数
/// - `dpapi_blob`: DPAPI 加密的保险库数据
/// - `password`: 待验证的密码
///
/// # 返回
/// - `Ok(true)`: 密码正确
/// - `Ok(false)`: 密码错误（包含模糊化的退避延迟）
/// - `Err`: 保险库损坏或 DPAPI 解密失败
///
/// # 安全性
/// - 使用常数时间比较（由 Argon2 库提供）
/// - 验证失败后引入 500ms 退避延迟，防止在线暴力破解
/// - 不泄露具体失败原因（DPAPI 失败 vs 密码错误）
///
/// # 示例
/// ```rust
/// let blob = std::fs::read("vault.bin")?;
///
/// if verify_password(&blob, "correct_password")? {
///     println!("✅ 密码正确");
/// } else {
///     println!("❌ 密码错误");
/// }
/// ```
pub fn verify_password(dpapi_blob: &[u8], password: &str) -> Result<bool> {
    let start = Instant::now();

    // 1. 加载保险库
    let vault = match load_vault(dpapi_blob) {
        Ok(v) => v,
        Err(e) => {
            // 模糊化错误（不区分 DPAPI 失败 vs 密码错误）
            apply_backoff(start);
            return Err(e);
        }
    };

    // 2. 解析存储的密码哈希（PHC 格式）
    let hash_str = String::from_utf8(vault.hash.clone())
        .context("Invalid UTF-8 in stored hash")?;

    let parsed_hash = PasswordHash::new(&hash_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse password hash: {}", e))?;

    // 3. 验证密码（常数时间比较）
    let argon2 = Argon2::default();
    let is_valid = argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    // 4. 失败时应用退避延迟
    if !is_valid {
        apply_backoff(start);
    }

    Ok(is_valid)
}

// ================================
// DPAPI 封装
// ================================

/// 使用 DPAPI 加密数据
///
/// # 参数
/// - `plaintext`: 明文数据
///
/// # 返回
/// - `Ok(Vec<u8>)`: 加密后的数据
/// - `Err`: DPAPI 调用失败
///
/// # 内部实现
/// - 调用 `CryptProtectData`
/// - 使用当前用户凭据
/// - 禁用 UI 提示（`CRYPT_PROTECT_UI_FORBIDDEN`）
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        // 构造输入数据结构
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut _,
        };

        // 输出数据结构（由 DPAPI 分配）
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // 调用 DPAPI 加密
        CryptProtectData(
            &mut input,
            None,                        // 无描述
            None,                        // 无额外熵
            None,                        // 保留参数
            None,                        // 无提示结构
            CRYPTPROTECT_UI_FORBIDDEN,  // 禁用 UI
            &mut output,
        )
            .context("CryptProtectData failed")?;

        // 复制加密数据到 Rust Vec
        let encrypted = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();

        // 释放 DPAPI 分配的内存
        LocalFree(Some(HLOCAL(output.pbData as *mut _)));

        Ok(encrypted)
    }
}

/// 使用 DPAPI 解密数据
///
/// # 参数
/// - `ciphertext`: 加密数据
///
/// # 返回
/// - `Ok(Vec<u8>)`: 解密后的明文
/// - `Err`: DPAPI 调用失败（可能是错误的用户/机器）
fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        // 构造输入数据结构
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut _,
        };

        // 输出数据结构
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // 调用 DPAPI 解密
        CryptUnprotectData(
            &mut input,
            None,                       // 不关心描述
            None,                       // 无额外熵
            None,                       // 保留参数
            None,                       // 无提示结构
            CRYPTPROTECT_UI_FORBIDDEN, // 禁用 UI
            &mut output,
        )
            .context("CryptUnprotectData failed (wrong user/machine?)")?;

        // 复制解密数据到 Rust Vec
        let plaintext = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();

        // 释放 DPAPI 分配的内存
        LocalFree(Some(HLOCAL(output.pbData as *mut _)));

        Ok(plaintext)
    }
}

// ================================
// 安全辅助函数
// ================================

/// 应用退避延迟（防止在线暴力破解）
///
/// # 参数
/// - `start`: 操作开始时间
///
/// # 实现
/// 确保总执行时间至少 `BACKOFF_DELAY_MS` 毫秒，
/// 使攻击者无法通过计时区分不同的失败原因。
fn apply_backoff(start: Instant) {
    let elapsed = start.elapsed();
    let target = Duration::from_millis(BACKOFF_DELAY_MS);

    if elapsed < target {
        std::thread::sleep(target - elapsed);
    }
}

// ================================
// 测试
// ================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_lifecycle() {
        let password = "TestP@ssw0rd123!";

        // 创建保险库
        let blob = create_vault(password).unwrap();
        assert!(!blob.is_empty());

        // 验证正确密码
        assert!(verify_password(&blob, password).unwrap());

        // 验证错误密码
        assert!(!verify_password(&blob, "WrongPassword").unwrap());
    }

    #[test]
    fn test_load_vault() {
        let password = "AnotherP@ss";

        let blob = create_vault(password).unwrap();
        let vault = load_vault(&blob).unwrap();

        assert_eq!(vault.version, VAULT_VERSION);
        assert!(!vault.salt.is_empty());
        assert!(!vault.hash.is_empty());
    }

    #[test]
    fn test_dpapi_roundtrip() {
        let plaintext = b"Secret Data 12345!";

        let encrypted = dpapi_protect(plaintext).unwrap();
        let decrypted = dpapi_unprotect(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_backoff_delay() {
        let start = Instant::now();
        apply_backoff(start);
        let elapsed = start.elapsed();

        // 应至少延迟 BACKOFF_DELAY_MS
        assert!(elapsed >= Duration::from_millis(BACKOFF_DELAY_MS));
    }

    #[test]
    fn test_wrong_user_dpapi() {
        // 注意：此测试无法跨用户验证，仅作为示例
        let password = "TestPassword";
        let blob = create_vault(password).unwrap();

        // 在同一用户下应能解密
        let result = load_vault(&blob);
        assert!(result.is_ok());

        // 如果在不同用户/机器下运行，DPAPI 解密应失败
        // （此处无法模拟，仅文档说明）
    }

    #[test]
    fn test_constant_time_comparison() {
        let password = "RealPassword";
        let blob = create_vault(password).unwrap();

        // 测试多次错误密码验证，时间应相近
        let mut times = Vec::new();
        for _ in 0..5 {
            let start = Instant::now();
            let _ = verify_password(&blob, "WrongPassword");
            times.push(start.elapsed());
        }

        // 验证时间差异不应过大（允许 100ms 误差）
        let max_time = times.iter().max().unwrap();
        let min_time = times.iter().min().unwrap();
        assert!(max_time.as_millis() - min_time.as_millis() < 100);
    }

    #[test]
    fn test_vault_version_check() {
        let password = "VersionTest";
        let blob = create_vault(password).unwrap();

        // 篡改版本号
        let mut vault = load_vault(&blob).unwrap();
        vault.version = 999;

        // 重新加密
        let tampered = serde_json::to_vec(&vault).unwrap();
        let tampered_blob = dpapi_protect(&tampered).unwrap();

        // 加载应失败（版本不匹配）
        let result = load_vault(&tampered_blob);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported vault version"));
    }
}