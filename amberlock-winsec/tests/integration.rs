//! amberlock-winsec 集成测试
//!
//! 本测试套件验证完整的 Windows 安全 API 封装功能。
//! 需要以管理员身份运行。

#[cfg(target_os = "windows")]
mod windows_tests {
    use amberlock_types::*;
    use amberlock_winsec::*;
    use std::fs;
    use tempfile::tempdir;

    /// 测试前提检查：确保以管理员身份运行
    fn check_admin_privileges() -> bool {
        // 尝试启用 SeSecurityPrivilege 作为管理员检查
        enable_privilege(Privilege::SeSecurity, true).is_ok()
    }

    #[test]
    fn test_capability_probe() {
        let cap = match token::probe_capability() {
            Ok(c) => c,
            Err(e) => {
                println!("⚠️ 能力探测失败: {:?}", e);
                return;
            }
        };

        println!("📊 系统能力报告:");
        println!("  - 完整性级别: {:?}", cap.caller_il);
        println!("  - SeSecurityPrivilege: {}", cap.has_se_security);
        println!("  - SeRelabelPrivilege: {}", cap.has_se_relabel);
        println!("  - 用户 SID: {}", cap.user_sid);

        // 基本断言
        assert!(matches!(
            cap.caller_il,
            LabelLevel::Medium | LabelLevel::High | LabelLevel::System
        ));
        assert!(cap.user_sid.starts_with("S-1-5-"));
    }

    #[test]
    fn test_single_file_label_lifecycle() {
        if !check_admin_privileges() {
            println!("⚠️ 跳过测试：需要管理员权限");
            return;
        }

        // 创建临时文件
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test_label.txt");
        fs::write(&test_file, b"test content").unwrap();

        let path = test_file.to_string_lossy();
        println!("🧪 测试文件: {}", path);

        // 1. 读取初始标签（应为默认 Medium）
        let initial_label = get_object_label(&path).unwrap();
        println!(
            "  初始标签: {:?} + {:?}",
            initial_label.level, initial_label.policy
        );

        // 2. 设置为 High + NW
        println!("  ⬆️ 设置为 High + NW...");
        set_mandatory_label(&path, LabelLevel::High, MandPolicy::NW).unwrap();

        // 3. 验证设置
        let high_label = get_object_label(&path).unwrap();
        println!(
            "  验证标签: {:?} + {:?}",
            high_label.level, high_label.policy
        );
        assert_eq!(high_label.level, LabelLevel::High);
        assert!(high_label.policy.contains(MandPolicy::NW));

        // 4. 尝试设置为 System（可能失败）
        println!("  ⬆️⬆️ 尝试设置为 System + NW...");
        match set_mandatory_label(&path, LabelLevel::System, MandPolicy::NW) {
            Ok(_) => {
                println!("  ✅ 成功设置 System 级别");
                let system_label = get_object_label(&path).unwrap();
                assert_eq!(system_label.level, LabelLevel::System);
            }
            Err(e) => {
                println!("  ⚠️ 无法设置 System 级别（预期行为）: {:?}", e);
            }
        }

        // 5. 移除标签
        println!("  ⬇️ 移除标签...");
        remove_mandatory_label(&path).unwrap();

        let final_label = get_object_label(&path).unwrap();
        println!("  最终标签: {:?}", final_label.level);
        // 注意：移除后可能仍显示为隐式 Medium

        println!("✅ 单文件标签生命周期测试通过");
    }

    #[test]
    fn test_directory_tree_operations() {
        if !check_admin_privileges() {
            println!("⚠️ 跳过测试：需要管理员权限");
            return;
        }

        // 创建临时目录树
        let temp_dir = tempdir().unwrap();
        let root = temp_dir.path();

        // 创建测试结构
        fs::create_dir(root.join("subdir1")).unwrap();
        fs::create_dir(root.join("subdir2")).unwrap();
        fs::write(root.join("file_root.txt"), b"root").unwrap();
        fs::write(root.join("subdir1/file1.txt"), b"sub1").unwrap();
        fs::write(root.join("subdir2/file2.txt"), b"sub2").unwrap();

        let root_str = root.to_string_lossy();
        println!("🧪 测试目录树: {}", root_str);

        let opts = TreeOptions {
            parallelism: 2,
            follow_symlinks: false,
            desired_level: LabelLevel::High,
            policy: MandPolicy::NW,
            stop_on_error: false,
        };

        // 应用标签到整个树
        println!("  ⬆️ 递归应用 High + NW...");
        let apply_stats = tree_apply_label(&root_str, &opts, |current, path, success| {
            let status = if success { "✅" } else { "❌" };
            println!("    [{}/5] {} {}", current, status, path);
        })
        .unwrap();

        println!("  📊 应用统计:");
        println!("    - 总数: {}", apply_stats.total);
        println!("    - 成功: {}", apply_stats.succeeded);
        println!("    - 失败: {}", apply_stats.failed);

        assert!(apply_stats.succeeded > 0, "至少应有部分成功");

        // 验证其中一个文件
        let verify_path = root.join("subdir1/file1.txt").to_string_lossy().to_string();
        let label = get_object_label(&verify_path).unwrap();
        assert_eq!(label.level, LabelLevel::High);

        // 移除所有标签
        println!("  ⬇️ 递归移除标签...");
        let remove_stats = tree_remove_label(&root_str, &opts, |current, path, success| {
            let status = if success { "✅" } else { "❌" };
            println!("    [{}/5] {} {}", current, status, path);
        })
        .unwrap();

        println!("  📊 移除统计:");
        println!("    - 总数: {}", remove_stats.total);
        println!("    - 成功: {}", remove_stats.succeeded);

        println!("✅ 目录树操作测试通过");
    }

    #[test]
    fn test_policy_combinations() {
        if !check_admin_privileges() {
            println!("⚠️ 跳过测试：需要管理员权限");
            return;
        }

        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("policy_test.txt");
        fs::write(&test_file, b"test").unwrap();

        let path = test_file.to_string_lossy();

        // 测试不同策略组合
        let test_cases = vec![
            ("仅 NW", MandPolicy::NW),
            ("NW + NR", MandPolicy::NW | MandPolicy::NR),
            (
                "NW + NR + NX",
                MandPolicy::NW | MandPolicy::NR | MandPolicy::NX,
            ),
        ];

        for (desc, policy) in test_cases {
            println!("  测试策略: {}", desc);

            set_mandatory_label(&path, LabelLevel::High, policy).unwrap();

            let label = get_object_label(&path).unwrap();
            assert!(label.policy.contains(MandPolicy::NW), "必须包含 NW");

            if policy.contains(MandPolicy::NR) {
                println!("    ⚠️ NR 策略已设置（对文件不保证生效）");
            }
            if policy.contains(MandPolicy::NX) {
                println!("    ⚠️ NX 策略已设置（对文件不保证生效）");
            }
        }

        remove_mandatory_label(&path).unwrap();
        println!("✅ 策略组合测试通过");
    }

    #[test]
    fn test_level_downgrade() {
        // 测试自动降级逻辑
        let cap = token::probe_capability().unwrap();

        let effective_system = compute_effective_level(LabelLevel::System, cap.has_se_relabel);

        if cap.has_se_relabel {
            println!("  ✅ 拥有 SeRelabelPrivilege，可设置 System 级");
            assert_eq!(effective_system, LabelLevel::System);
        } else {
            println!("  ⚠️ 缺少 SeRelabelPrivilege，System 级将降为 High");
            assert_eq!(effective_system, LabelLevel::High);
        }

        // High 级不应降级
        let effective_high = compute_effective_level(LabelLevel::High, false);
        assert_eq!(effective_high, LabelLevel::High);

        println!("✅ 级别降级逻辑测试通过");
    }

    #[test]
    fn test_error_handling() {
        // 测试对不存在路径的错误处理
        let invalid_path = "C:\\NonExistentPath\\test.txt";

        let result = get_object_label(invalid_path);
        assert!(result.is_err(), "应返回错误");

        if let Err(e) = result {
            println!("  预期错误: {:?}", e);
        }

        println!("✅ 错误处理测试通过");
    }
}

#[cfg(not(target_os = "windows"))]
mod non_windows_tests {
    #[test]
    fn test_non_windows_platform() {
        println!("Warning: amberlock-winsec Only supports Windows Platform");
        println!(" 当前平台不运行任何测试");
    }
}
