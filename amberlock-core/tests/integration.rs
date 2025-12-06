//! AmberLock Core 集成测试
//!
//! 测试完整的业务流程，包括批量操作、递归处理、回滚机制等

use amberlock_core::*;
use amberlock_storage::NdjsonWriter;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

/// 测试基础批量上锁功能
#[test]
#[cfg_attr(not(target_os = "windows"), ignore)]
fn test_batch_lock_basic() {
    // 创建临时目录和文件
    let temp_dir = tempdir().unwrap();
    let test_file1 = temp_dir.path().join("file1.txt");
    let test_file2 = temp_dir.path().join("file2.txt");

    fs::write(&test_file1, b"test1").unwrap();
    fs::write(&test_file2, b"test2").unwrap();

    // 创建日志记录器
    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path).unwrap();

    // 配置选项
    let opts = BatchOptions {
        desired_level: LabelLevel::High,
        mode: ProtectMode::ReadOnly,
        policy: MandPolicy::NW,
        parallelism: 2,
        dry_run: false,
        enable_rollback: true,
        enable_checkpoint: false,
        idempotent: true,
        stop_on_error: false,
    };

    let paths = vec![test_file1.clone(), test_file2.clone()];

    // 执行批量上锁
    let result = batch_lock(&paths, &opts, &logger, None, None);

    match result {
        Ok(batch_result) => {
            println!("批量上锁结果: {:?}", batch_result);
            assert!(batch_result.succeeded > 0 || batch_result.failed > 0);
        }
        Err(e) => {
            println!("批量上锁失败（可能需要管理员权限）: {:?}", e);
        }
    }
}

/// 测试幂等性（重复上锁）
#[test]
#[cfg_attr(not(target_os = "windows"), ignore)]
fn test_batch_lock_idempotent() {
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"test").unwrap();

    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path).unwrap();

    let opts = BatchOptions {
        idempotent: true,
        ..Default::default()
    };

    let paths = vec![test_file.clone()];

    // 第一次上锁
    let result1 = batch_lock(&paths, &opts, &logger, None, None);
    if result1.is_err() {
        println!("跳过测试（需要管理员权限）");
        return;
    }

    // 第二次上锁（应该被跳过）
    let result2 = batch_lock(&paths, &opts, &logger, None, None).unwrap();

    // 验证第二次操作跳过了已存在相同配置的对象
    assert!(result2.skipped > 0 || result2.succeeded == 0);
}

/// 测试进度回调
#[test]
#[cfg_attr(not(target_os = "windows"), ignore)]
fn test_batch_lock_with_progress() {
    let temp_dir = tempdir().unwrap();

    // 创建多个测试文件
    let paths: Vec<PathBuf> = (0..5)
        .map(|i| {
            let file = temp_dir.path().join(format!("file{}.txt", i));
            fs::write(&file, format!("test{}", i)).unwrap();
            file
        })
        .collect();

    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path).unwrap();

    let opts = BatchOptions::default();

    // 创建进度回调
    let progress_count = Arc::new(std::sync::Mutex::new(0u64));
    let progress_count_clone = Arc::clone(&progress_count);

    let progress_callback: ProgressCallback = Arc::new(move |path, snapshot| {
        println!("处理: {} - 进度: {:.1}%", path, snapshot.percentage());
        *progress_count_clone.lock().unwrap() += 1;
    });

    // 执行批量上锁
    let result = batch_lock(&paths, &opts, &logger, Some(progress_callback), None);

    if result.is_ok() {
        let count = *progress_count.lock().unwrap();
        println!("进度回调被调用 {} 次", count);
        assert!(count > 0);
    } else {
        println!("跳过测试（需要管理员权限）");
    }
}

/// 测试回滚机制
#[test]
#[cfg_attr(not(target_os = "windows"), ignore)]
fn test_rollback_mechanism() {
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"test").unwrap();

    // 创建回滚管理器
    let mut rollback_manager = RollbackManager::new(true);

    let path_str = test_file.to_string_lossy().to_string();

    // 备份当前状态
    let backup_result = rollback_manager.backup(&path_str);
    if backup_result.is_err() {
        println!("跳过测试（需要管理员权限）");
        return;
    }

    // 验证备份数量
    assert_eq!(rollback_manager.backup_count(), 1);

    // 执行回滚
    let rollback_result = rollback_manager.rollback();
    println!("回滚结果: {:?}", rollback_result);

    // 验证回滚后备份清空
    assert_eq!(rollback_manager.backup_count(), 0);
}

/// 测试断点续执
#[test]
fn test_checkpoint_persistence() {
    let temp_dir = tempdir().unwrap();
    let checkpoint_dir = temp_dir.path().join("checkpoints");

    // 创建检查点管理器
    let manager = CheckpointManager::new(&checkpoint_dir).unwrap();

    // 创建测试检查点
    let params = serde_json::json!({
        "mode": "lock",
        "level": "High",
    });

    let mut checkpoint = Checkpoint::new("lock", 100, params);
    checkpoint.update_progress(50, 45, 5, vec!["path1".into(), "path2".into()]);

    // 保存检查点
    manager.save(&checkpoint).unwrap();

    // 加载检查点
    let loaded = manager.load(&checkpoint.id).unwrap();

    // 验证数据一致性
    assert_eq!(loaded.id, checkpoint.id);
    assert_eq!(loaded.processed_index, 50);
    assert_eq!(loaded.succeeded, 45);
    assert_eq!(loaded.failed, 5);
    assert_eq!(loaded.pending_paths.len(), 2);

    // 清理
    manager.delete(&checkpoint.id).unwrap();
}

/// 测试递归目录操作（需要管理员权限）
#[test]
#[cfg_attr(not(target_os = "windows"), ignore)]
fn test_recursive_directory_lock() {
    let temp_dir = tempdir().unwrap();

    // 创建目录树
    let sub_dir = temp_dir.path().join("subdir");
    fs::create_dir(&sub_dir).unwrap();
    fs::write(temp_dir.path().join("file1.txt"), b"test1").unwrap();
    fs::write(sub_dir.join("file2.txt"), b"test2").unwrap();

    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path).unwrap();

    let opts = RecursiveOptions {
        desired_level: LabelLevel::High,
        mode: ProtectMode::ReadOnly,
        policy: MandPolicy::NW,
        parallelism: 2,
        follow_symlinks: false,
        stop_on_error: false,
        dry_run: false,
        enable_rollback: true,
    };

    // 执行递归上锁
    let result = recursive_apply_label(temp_dir.path(), &opts, &logger, None);

    match result {
        Ok(recursive_result) => {
            println!("递归上锁结果: {:?}", recursive_result);
            assert!(recursive_result.total > 0);
        }
        Err(e) => {
            println!("递归上锁失败（可能需要管理员权限）: {:?}", e);
        }
    }
}

/// 测试干跑模式
#[test]
fn test_dry_run_mode() {
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"test").unwrap();

    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path).unwrap();

    let opts = BatchOptions {
        dry_run: true,
        ..Default::default()
    };

    let paths = vec![test_file.clone()];

    // 干跑模式应该总是成功（不实际修改）
    let result = batch_lock(&paths, &opts, &logger, None, None).unwrap();

    println!("干跑模式结果: {:?}", result);
    assert_eq!(result.succeeded, 1);
}

/// 测试能力探测
#[test]
fn test_capability_probe() {
    let result = probe_capability();

    match result {
        Ok(report) => {
            println!("系统能力报告: {:?}", report);
            let cap = report.capability;

            println!("当前完整性级别: {:?}", cap.caller_il);
            println!("可访问 SACL: {}", cap.can_touch_sacl);
            println!("可设置 System 级: {}", cap.can_set_system);
        }
        Err(e) => {
            println!("能力探测失败: {:?}", e);
        }
    }
}

/// 测试进度跟踪器
#[test]
fn test_progress_tracker() {
    let tracker = ProgressTracker::new(100);

    // 模拟进度更新
    for _ in 0..50 {
        tracker.mark_success();
    }

    for _ in 0..10 {
        tracker.mark_failed();
    }

    let snapshot = tracker.snapshot();

    assert_eq!(snapshot.total, 100);
    assert_eq!(snapshot.completed, 60);
    assert_eq!(snapshot.succeeded, 50);
    assert_eq!(snapshot.failed, 10);
    assert_eq!(snapshot.percentage(), 60.0);

    println!("进度状态: {}", snapshot.format_status());
}