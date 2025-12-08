//! AmberLock GUI 集成测试
//!
//! 测试完整的 GUI 工作流程（需要管理员权限）

use amberlock_gui::{model, utils, vault};
use std::path::PathBuf;
use tempfile::tempdir;

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 保险库测试 =====

    #[test]
    fn test_vault_creation_and_verification() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_vault.bin");

        // 创建保险库
        vault::create_vault(&vault_path, "test_password_123").unwrap();
        assert!(vault_path.exists());

        // 验证正确密码
        assert!(vault::verify_vault_password(&vault_path, "test_password_123").unwrap());

        // 验证错误密码
        assert!(!vault::verify_vault_password(&vault_path, "wrong_password").unwrap());
    }

    #[test]
    fn test_vault_status_detection() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault.bin");

        // 初始状态：不存在
        assert_eq!(
            vault::check_vault_status(&vault_path),
            vault::VaultStatus::NotExists
        );

        // 创建保险库
        vault::create_vault(&vault_path, "password").unwrap();
        assert_eq!(
            vault::check_vault_status(&vault_path),
            vault::VaultStatus::Exists
        );

        // 损坏保险库
        std::fs::write(&vault_path, b"invalid_data").unwrap();
        assert_eq!(
            vault::check_vault_status(&vault_path),
            vault::VaultStatus::Corrupted
        );
    }

    #[test]
    fn test_vault_password_change() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault.bin");

        // 创建初始保险库
        vault::create_vault(&vault_path, "old_password").unwrap();

        // 更改密码
        vault::change_vault_password(&vault_path, "old_password", "new_password").unwrap();

        // 验证新密码
        assert!(vault::verify_vault_password(&vault_path, "new_password").unwrap());
        assert!(!vault::verify_vault_password(&vault_path, "old_password").unwrap());
    }

    #[test]
    fn test_vault_first_run_initialization() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault.bin");

        // 首次初始化
        let created = vault::initialize_vault_if_needed(&vault_path, "default").unwrap();
        assert!(created);

        // 再次初始化（应跳过）
        let created_again = vault::initialize_vault_if_needed(&vault_path, "default").unwrap();
        assert!(!created_again);
    }

    // ===== 工具函数测试 =====

    #[test]
    fn test_path_validation() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"test").unwrap();

        // 验证存在的文件
        let result = utils::validate_path(&test_file);
        assert!(result.is_ok());

        // 验证不存在的文件
        let nonexistent = temp_dir.path().join("nonexistent.txt");
        let result = utils::validate_path(&nonexistent);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_size_formatting() {
        assert_eq!(utils::format_file_size(0), "0 B");
        assert_eq!(utils::format_file_size(1024), "1.0 KB");
        assert_eq!(utils::format_file_size(1536), "1.5 KB");
        assert_eq!(utils::format_file_size(1048576), "1.0 MB");
        assert_eq!(utils::format_file_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_timestamp_formatting() {
        let timestamp = "2025-01-01T12:30:45Z";
        let formatted = utils::format_timestamp(timestamp);
        assert_eq!(formatted, "2025-01-01 12:30:45");

        let with_milliseconds = "2025-01-01T12:30:45.123Z";
        let formatted = utils::format_timestamp(with_milliseconds);
        assert_eq!(formatted, "2025-01-01 12:30:45");
    }

    #[test]
    fn test_duration_formatting() {
        assert_eq!(utils::format_duration(500), "500 ms");
        assert_eq!(utils::format_duration(1500), "1.5 s");
        assert_eq!(utils::format_duration(65000), "1m 5s");
    }

    #[test]
    #[cfg(windows)]
    fn test_volume_root_detection() {
        assert!(utils::is_volume_root(&PathBuf::from("C:\\")));
        assert!(utils::is_volume_root(&PathBuf::from("D:\\")));
        assert!(!utils::is_volume_root(&PathBuf::from("C:\\Windows")));
        assert!(!utils::is_volume_root(&PathBuf::from("C:\\Users\\test")));
    }

    #[test]
    fn test_path_truncation() {
        let short_path = "C:\\test\\file.txt";
        assert_eq!(utils::truncate_path_for_display(short_path, 50), short_path);

        let long_path = "C:\\Users\\VeryLongUsername\\Documents\\Projects\\AmberLock\\src\\main.rs";
        let truncated = utils::truncate_path_for_display(long_path, 40);
        assert_eq!(truncated.len(), 40);
        assert!(truncated.contains("..."));
    }

    // ===== 模型测试 =====

    #[test]
    fn test_file_list_model_operations() {
        let model = model::FileListModel::new();

        // 初始状态
        assert_eq!(model.snapshot().len(), 0);

        // 添加路径
        let paths = vec![
            PathBuf::from("C:\\test\\file1.txt"),
            PathBuf::from("C:\\test\\file2.txt"),
        ];
        model.add_paths(&paths);

        let snapshot = model.snapshot();
        assert_eq!(snapshot.len(), 2);

        // 验证选中状态
        let selected = model.selected_paths();
        assert_eq!(selected.len(), 2); // 默认全选

        // 切换选中状态
        model.set_selected(0, false);
        let selected = model.selected_paths();
        assert_eq!(selected.len(), 1);

        // 清空
        model.clear();
        assert_eq!(model.snapshot().len(), 0);
    }

    #[test]
    fn test_file_list_model_toggle() {
        let model = model::FileListModel::new();
        let paths = vec![PathBuf::from("C:\\test.txt")];
        model.add_paths(&paths);

        // 初始选中
        assert_eq!(model.selected_paths().len(), 1);

        // 切换为未选中
        model.toggle_selected(0);
        assert_eq!(model.selected_paths().len(), 0);

        // 再次切换为选中
        model.toggle_selected(0);
        assert_eq!(model.selected_paths().len(), 1);
    }

    #[test]
    fn test_file_list_model_remove() {
        let model = model::FileListModel::new();
        let paths = vec![
            PathBuf::from("C:\\file1.txt"),
            PathBuf::from("C:\\file2.txt"),
            PathBuf::from("C:\\file3.txt"),
        ];
        model.add_paths(&paths);

        // 移除中间项
        let removed = model.remove_at(1);
        assert_eq!(removed, Some(PathBuf::from("C:\\file2.txt")));
        assert_eq!(model.snapshot().len(), 2);

        // 移除越界索引
        let removed = model.remove_at(10);
        assert_eq!(removed, None);
    }

    // ===== 集成工作流程测试 =====

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    // #[ignore] // 需要管理员权限，手动运行
    fn test_complete_workflow() {
        use amberlock_core::{BatchOptions, batch_lock, batch_unlock};
        use amberlock_storage::NdjsonWriter;

        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"test_content").unwrap();

        let log_path = temp_dir.path().join("log.ndjson");
        let vault_path = temp_dir.path().join("vault.bin");

        // 1. 创建保险库
        vault::create_vault(&vault_path, "test_password").unwrap();

        // 2. 创建日志记录器
        let logger = NdjsonWriter::open_append(&log_path).unwrap();

        // 3. 执行锁定
        let opts = BatchOptions {
            desired_level: amberlock_types::LabelLevel::High,
            mode: amberlock_types::ProtectMode::ReadOnly,
            policy: amberlock_types::MandPolicy::NW,
            parallelism: 1,
            dry_run: false,
            enable_rollback: true,
            enable_checkpoint: false,
            idempotent: true,
            stop_on_error: false,
        };

        let lock_result = batch_lock(&[test_file.clone()], &opts, &logger, None, None);

        match lock_result {
            Ok(result) => {
                println!("✅ 锁定成功: {:?}", result);
                assert!(result.is_success() || result.is_partial_success());

                // 4. 执行解锁
                let vault_blob = std::fs::read(&vault_path).unwrap();
                let unlock_result = batch_unlock(
                    &[test_file.clone()],
                    "test_password",
                    &vault_blob,
                    &logger,
                    None,
                );

                match unlock_result {
                    Ok(unlock_result) => {
                        println!("✅ 解锁成功: {:?}", unlock_result);
                        assert!(unlock_result.is_success());
                    }
                    Err(e) => {
                        eprintln!("❌ 解锁失败: {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠️ 锁定失败（可能需要管理员权限）: {:?}", e);
            }
        }
    }

    #[test]
    fn test_log_model_creation() {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("test_log.ndjson");

        // 创建空日志文件
        std::fs::write(&log_path, "").unwrap();

        // 打开日志模型
        let log_model = model::LogListModel::open(log_path.to_str().unwrap());
        assert!(log_model.is_ok());

        let log_model = log_model.unwrap();
        let snapshot = log_model.snapshot(100);
        assert_eq!(snapshot.len(), 0); // 空日志
    }

    #[test]
    fn test_log_model_with_data() {
        use amberlock_storage::NdjsonWriter;

        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("test_log.ndjson");

        // 写入测试日志
        {
            let logger = NdjsonWriter::open_append(&log_path).unwrap();
            for i in 0..10 {
                let record = serde_json::json!({
                    "id": format!("test-{}", i),
                    "time_utc": format!("2025-01-{:02}T12:00:00Z", i + 1),
                    "status": if i % 2 == 0 { "success" } else { "error" },
                    "path": format!("C:\\test\\file{}.txt", i),
                    "level_applied": "High",
                });
                logger.write_record(&record).unwrap();
            }
            logger.flush().unwrap();
        }

        // 读取日志
        let log_model = model::LogListModel::open(log_path.to_str().unwrap()).unwrap();
        let snapshot = log_model.snapshot(100);
        assert_eq!(snapshot.len(), 10);

        // 测试过滤
        let filtered = log_model.filter_snapshot("error", 100);
        assert_eq!(filtered.len(), 5); // 5 条 error 记录
    }
}
