//! amberlock-auth 集成测试
//!
//! 验证完整的密码保险库生命周期和安全特性

use amberlock_auth::*;
use std::fs;
use std::time::Instant;
use tempfile::NamedTempFile;

#[test]
fn test_create_and_verify_vault() {
    let password = "SuperSecureP@ssw0rd!123";

    // 创建保险库
    let vault_blob = create_vault(password).expect("Failed to create vault");

    // 验证正确密码
    assert!(
        verify_password(&vault_blob, password).expect("Verification failed"),
        "应接受正确密码"
    );

    // 验证错误密码
    assert!(
        !verify_password(&vault_blob, "WrongPassword").expect("Verification failed"),
        "应拒绝错误密码"
    );
}

#[test]
fn test_vault_persistence() {
    let password = "PersistentP@ss";
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let path = temp_file.path();

    // 创建并保存保险库
    let vault_blob = create_vault(password).expect("Failed to create vault");
    fs::write(path, &vault_blob).expect("Failed to write vault");

    // 从文件加载并验证
    let loaded_blob = fs::read(path).expect("Failed to read vault");
    assert!(
        verify_password(&loaded_blob, password).expect("Verification failed"),
        "从文件加载的保险库应可验证"
    );
}

#[test]
fn test_load_vault_structure() {
    let password = "StructureTest";

    let vault_blob = create_vault(password).expect("Failed to create vault");
    let vault = load_vault(&vault_blob).expect("Failed to load vault");

    // 验证数据结构
    assert_eq!(vault.version, 1, "版本号应为 1");
    assert!(!vault.salt.is_empty(), "盐不应为空");
    assert!(!vault.hash.is_empty(), "哈希不应为空");
    assert!(vault.params.contains("m=19456"), "参数应包含内存成本");
    assert!(vault.params.contains("t=2"), "参数应包含时间成本");
    assert!(vault.params.contains("p=1"), "参数应包含并行度");
}

#[test]
fn test_multiple_passwords() {
    let passwords = vec![
        "Password1!",
        "Another$ecure2",
        "VeryL0ng@ndCompl3xP@ssw0rd#123",
        "简单密码", // 测试 Unicode
    ];

    for password in passwords {
        let blob = create_vault(password).expect("Failed to create vault");

        // 验证正确密码
        assert!(
            verify_password(&blob, password).expect("Verification failed"),
            "密码 '{}' 应验证通过",
            password
        );

        // 验证错误密码
        assert!(
            !verify_password(&blob, "NotTheRightPassword").expect("Verification failed"),
            "错误密码应验证失败"
        );
    }
}

#[test]
fn test_timing_attack_resistance() {
    let password = "TimingTestP@ss";
    let blob = create_vault(password).expect("Failed to create vault");

    // 测试多次错误密码验证，时间应相近（退避机制）
    let mut durations = Vec::new();

    for _ in 0..5 {
        let start = Instant::now();
        let _ = verify_password(&blob, "WrongPassword");
        durations.push(start.elapsed());
    }

    // 验证所有验证都至少耗时 500ms（退避延迟）
    for duration in &durations {
        assert!(
            duration.as_millis() >= 500,
            "验证应至少耗时 500ms（退避延迟）"
        );
    }

    // 验证时间差异不应过大（允许 200ms 误差）
    let max = durations.iter().max().unwrap();
    let min = durations.iter().min().unwrap();
    let diff = max.as_millis() - min.as_millis();
    assert!(diff < 200, "验证时间差异应小于 200ms，实际差异: {}ms", diff);
}

#[test]
fn test_vault_independence() {
    let password1 = "FirstP@ss";
    let password2 = "SecondP@ss";

    // 创建两个独立的保险库
    let blob1 = create_vault(password1).expect("Failed to create vault 1");
    let blob2 = create_vault(password2).expect("Failed to create vault 2");

    // 验证保险库独立性
    assert_ne!(blob1, blob2, "两个保险库的密文应不同");

    // 交叉验证应失败
    assert!(
        !verify_password(&blob1, password2).expect("Verification failed"),
        "保险库 1 不应接受保险库 2 的密码"
    );
    assert!(
        !verify_password(&blob2, password1).expect("Verification failed"),
        "保险库 2 不应接受保险库 1 的密码"
    );
}

#[test]
fn test_empty_password() {
    // 测试空密码（不推荐但应支持）
    let blob = create_vault("").expect("Failed to create vault with empty password");
    assert!(
        verify_password(&blob, "").expect("Verification failed"),
        "应接受空密码"
    );
}

#[test]
fn test_long_password() {
    // 测试超长密码（1024 字符）
    let long_password = "a".repeat(1024);
    let blob = create_vault(&long_password).expect("Failed to create vault with long password");
    assert!(
        verify_password(&blob, &long_password).expect("Verification failed"),
        "应接受超长密码"
    );
}

#[test]
fn test_corrupted_vault() {
    let password = "CorruptTest";
    let mut blob = create_vault(password).expect("Failed to create vault");

    // 篡改密文中间的字节
    if blob.len() > 10 {
        let tmp = blob.len() / 2;
        blob[tmp] ^= 0xFF;
    }

    // 解密应失败
    let result = verify_password(&blob, password);
    assert!(result.is_err(), "篡改的保险库应解密失败");
}

#[test]
fn test_salt_uniqueness() {
    let password = "SamePassword";

    // 创建多个保险库使用相同密码
    let blob1 = create_vault(password).expect("Failed to create vault 1");
    let blob2 = create_vault(password).expect("Failed to create vault 2");
    let blob3 = create_vault(password).expect("Failed to create vault 3");

    // 验证密文不同（因为盐不同）
    assert_ne!(blob1, blob2, "相同密码的保险库应生成不同密文");
    assert_ne!(blob2, blob3, "相同密码的保险库应生成不同密文");
    assert_ne!(blob1, blob3, "相同密码的保险库应生成不同密文");

    // 但都应能用相同密码验证
    assert!(verify_password(&blob1, password).unwrap());
    assert!(verify_password(&blob2, password).unwrap());
    assert!(verify_password(&blob3, password).unwrap());
}

#[test]
fn test_unicode_passwords() {
    let unicode_passwords = vec![
        "中文密码123",
        "日本語パスワード",
        "한국어비밀번호",
        "Русский пароль",
        "🔒🔑🛡️ Emoji密码",
    ];

    for password in unicode_passwords {
        let blob = create_vault(password).expect("Failed to create vault with Unicode password");
        assert!(
            verify_password(&blob, password).expect("Verification failed"),
            "Unicode 密码 '{}' 应验证通过",
            password
        );
    }
}

#[test]
fn test_case_sensitivity() {
    let password = "CaseSensitive";

    let blob = create_vault(password).expect("Failed to create vault");

    // 验证大小写敏感
    assert!(
        verify_password(&blob, password).unwrap(),
        "正确大小写应通过"
    );
    assert!(
        !verify_password(&blob, "casesensitive").unwrap(),
        "错误大小写应失败"
    );
    assert!(
        !verify_password(&blob, "CASESENSITIVE").unwrap(),
        "错误大小写应失败"
    );
}

#[test]
#[ignore] // 此测试需要较长时间
fn test_performance() {
    use std::time::Instant;

    let password = "PerformanceTest";

    // 测试创建保险库的性能
    let start = Instant::now();
    let blob = create_vault(password).expect("Failed to create vault");
    let create_duration = start.elapsed();

    println!("创建保险库耗时: {:?}", create_duration);

    // Argon2 应在合理时间内完成（< 5 秒）
    assert!(create_duration.as_secs() < 5, "创建保险库应在 5 秒内完成");

    // 测试验证性能
    let start = Instant::now();
    let _ = verify_password(&blob, password);
    let verify_duration = start.elapsed();

    println!("验证密码耗时: {:?}", verify_duration);

    // 验证应在退避延迟 + 合理时间内完成（< 6 秒）
    assert!(verify_duration.as_secs() < 6, "验证密码应在 6 秒内完成");
}
