//! AmberLock Core 基础使用示例
//!
//! 演示核心功能的基本用法：
//! - 批量上锁/解锁
//! - 进度回调
//! - 回滚机制
//! - 断点续执
//! - 递归目录操作

use amberlock_core::*;
use amberlock_storage::NdjsonWriter;
use std::path::PathBuf;
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    println!("=== AmberLock Core 功能演示 ===\n");

    // 1. 系统能力探测
    example_capability_probe()?;

    // 2. 批量上锁
    example_batch_lock()?;

    // 3. 带进度回调的上锁
    example_lock_with_progress()?;

    // 4. 回滚机制演示
    example_rollback()?;

    // 5. 断点续执演示
    example_checkpoint()?;

    // 6. 递归目录操作
    example_recursive_lock()?;

    println!("\n=== 演示完成 ===");
    Ok(())
}

/// 示例1：系统能力探测
fn example_capability_probe() -> anyhow::Result<()> {
    println!("--- 示例1: 系统能力探测 ---");

    let report = probe_capability()?;
    let cap = report.capability;

    println!("✓ 当前完整性级别: {:?}", cap.caller_il);
    println!("✓ 可访问 SACL: {}", cap.can_touch_sacl);
    println!("✓ 可设置 System 级: {}", cap.can_set_system);

    if !cap.can_touch_sacl {
        println!("⚠️  警告：缺少 SeSecurityPrivilege，需要管理员权限");
    }

    if !cap.can_set_system {
        println!("ℹ️  提示：无法设置 System 级别，将自动降级为 High");
    }

    println!();
    Ok(())
}

/// 示例2：基础批量上锁
fn example_batch_lock() -> anyhow::Result<()> {
    println!("--- 示例2: 批量上锁 ---");

    // 创建临时测试文件（实际使用时替换为真实路径）
    let temp_dir = tempfile::tempdir()?;
    let test_files: Vec<PathBuf> = (0..3)
        .map(|i| {
            let file = temp_dir.path().join(format!("test{}.txt", i));
            std::fs::write(&file, format!("test content {}", i)).unwrap();
            file
        })
        .collect();

    println!("创建了 {} 个测试文件", test_files.len());

    // 创建日志记录器
    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path)?;

    // 配置批量上锁选项
    let opts = BatchOptions {
        desired_level: LabelLevel::High,
        mode: ProtectMode::ReadOnly,
        policy: MandPolicy::NW,
        parallelism: 2,
        dry_run: false, // 设为 true 可以测试而不实际修改
        enable_rollback: true,
        enable_checkpoint: false,
        idempotent: true,
        stop_on_error: false,
    };

    // 执行批量上锁
    match batch_lock(&test_files, &opts, &logger, None, None) {
        Ok(result) => {
            println!("✓ 上锁完成:");
            println!("  - 总计: {}", result.total);
            println!("  - 成功: {}", result.succeeded);
            println!("  - 失败: {}", result.failed);
            println!("  - 跳过: {}", result.skipped);
            if result.downgraded > 0 {
                println!("  - 降级: {} (System → High)", result.downgraded);
            }
        }
        Err(e) => {
            println!("❌ 上锁失败: {:?}", e);
            println!("   （可能需要管理员权限）");
        }
    }

    println!();
    Ok(())
}

/// 示例3：带进度回调的上锁
fn example_lock_with_progress() -> anyhow::Result<()> {
    println!("--- 示例3: 带进度回调的上锁 ---");

    let temp_dir = tempfile::tempdir()?;
    let test_files: Vec<PathBuf> = (0..5)
        .map(|i| {
            let file = temp_dir.path().join(format!("file{}.txt", i));
            std::fs::write(&file, "test").unwrap();
            file
        })
        .collect();

    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path)?;

    let opts = BatchOptions::default();

    // 创建进度回调
    let progress_callback: ProgressCallback = Arc::new(|path, snapshot| {
        println!(
            "  [{:.1}%] 正在处理: {}",
            snapshot.percentage(),
            path.split('\\').last().unwrap_or(path)
        );

        if let Some(eta) = snapshot.eta() {
            println!("    预计剩余时间: {:.1}秒", eta.as_secs_f64());
        }
    });

    match batch_lock(&test_files, &opts, &logger, Some(progress_callback), None) {
        Ok(result) => {
            println!("✓ 操作完成: {}/{} 成功", result.succeeded, result.total);
        }
        Err(e) => {
            println!("❌ 操作失败: {:?}", e);
        }
    }

    println!();
    Ok(())
}

/// 示例4：回滚机制演示
fn example_rollback() -> anyhow::Result<()> {
    println!("--- 示例4: 回滚机制 ---");

    // 创建回滚管理器（启用自动回滚）
    let mut rollback_manager = RollbackManager::new(true);

    let temp_dir = tempfile::tempdir()?;
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, "test")?;

    let path_str = test_file.to_string_lossy().to_string();

    // 备份原始状态
    println!("备份对象原始状态...");
    match rollback_manager.backup(&path_str) {
        Ok(_) => {
            println!("✓ 已备份 1 个对象");
        }
        Err(e) => {
            println!("⚠️  备份失败: {:?} （可能需要管理员权限）", e);
            return Ok(());
        }
    }

    // 模拟操作失败场景
    println!("模拟操作失败...");

    // 执行回滚
    println!("执行回滚...");
    let rollback_result = rollback_manager.rollback();

    println!("✓ 回滚完成:");
    println!("  - 总计: {}", rollback_result.total);
    println!("  - 成功恢复: {}", rollback_result.succeeded);
    println!("  - 恢复失败: {}", rollback_result.failed);

    println!();
    Ok(())
}

/// 示例5：断点续执演示
fn example_checkpoint() -> anyhow::Result<()> {
    println!("--- 示例5: 断点续执 ---");

    let temp_dir = tempfile::tempdir()?;
    let checkpoint_dir = temp_dir.path().join("checkpoints");

    // 创建检查点管理器
    let manager = CheckpointManager::new(&checkpoint_dir)?;

    // 模拟大规模操作
    let params = serde_json::json!({
        "mode": "lock",
        "level": "High",
        "policy": "NW",
    });

    let mut checkpoint = Checkpoint::new("lock", 1000, params);

    // 模拟处理进度
    println!("开始大规模操作...");
    for i in (0..=1000).step_by(100) {
        checkpoint.update_progress(
            i,
            i.saturating_sub(10),
            10,
            vec!["pending1".into(), "pending2".into()],
        );

        println!("  进度: {}% ({}/{})", checkpoint.percentage(), i, 1000);

        // 定期保存检查点
        manager.save(&checkpoint)?;
    }

    println!("✓ 操作完成，检查点已保存");
    println!("  检查点 ID: {}", checkpoint.id);

    // 模拟从检查点恢复
    println!("\n模拟从检查点恢复...");
    let loaded = manager.load(&checkpoint.id)?;
    println!("✓ 检查点已加载:");
    println!("  - 已处理: {}/{}", loaded.processed_index, loaded.total_count);
    println!("  - 成功: {}", loaded.succeeded);
    println!("  - 失败: {}", loaded.failed);

    // 清理
    manager.delete(&checkpoint.id)?;
    println!("✓ 检查点已清理");

    println!();
    Ok(())
}

/// 示例6：递归目录操作
fn example_recursive_lock() -> anyhow::Result<()> {
    println!("--- 示例6: 递归目录操作 ---");

    let temp_dir = tempfile::tempdir()?;

    // 创建目录树
    let sub_dir1 = temp_dir.path().join("dir1");
    let sub_dir2 = temp_dir.path().join("dir1/dir2");
    std::fs::create_dir_all(&sub_dir2)?;

    std::fs::write(temp_dir.path().join("root.txt"), "root")?;
    std::fs::write(sub_dir1.join("file1.txt"), "file1")?;
    std::fs::write(sub_dir2.join("file2.txt"), "file2")?;

    println!("创建了测试目录树:");
    println!("  root.txt");
    println!("  dir1/");
    println!("    file1.txt");
    println!("    dir2/");
    println!("      file2.txt");

    let log_path = temp_dir.path().join("operations.ndjson");
    let logger = NdjsonWriter::open_append(&log_path)?;

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

    // 创建进度回调
    let progress_callback: ProgressCallback = Arc::new(|path, snapshot| {
        println!(
            "  [{:.1}%] {}",
            snapshot.percentage(),
            path.split('\\').last().unwrap_or(path)
        );
    });

    println!("\n开始递归上锁...");
    match recursive_apply_label(temp_dir.path(), &opts, &logger, Some(progress_callback)) {
        Ok(result) => {
            println!("\n✓ 递归上锁完成:");
            println!("  - 总计: {}", result.total);
            println!("  - 成功: {}", result.succeeded);
            println!("  - 失败: {}", result.failed);
            println!("  - 跳过: {}", result.skipped);
        }
        Err(e) => {
            println!("\n❌ 递归上锁失败: {:?}", e);
            println!("   （可能需要管理员权限）");
        }
    }

    println!();
    Ok(())
}