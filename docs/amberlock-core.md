# AmberLock Core

核心业务编排库，提供完整的文件锁定/解锁功能。

## 功能特性

### ✅ 已实现

- **批量操作**
    - 并发处理（可配置并发度）
    - 幂等性（重复操作不报错）
    - 自动降级（System → High）
    - 干跑模式（预览不修改）

- **递归目录处理**
    - 整合 `winsec::tree_apply_label`
    - 目录树批量上锁/解锁
    - 卷根特殊保护（C:\ 等）

- **进度跟踪**
    - 实时进度回调
    - 统计信息（成功/失败/跳过）
    - ETA 估算
    - 取消标志

- **回滚机制**
    - 操作前自动备份
    - 失败时批量恢复
    - RAII 自动回滚
    - 手动提交（禁用自动回滚）

- **断点续执**
    - 检查点保存/加载
    - 进度恢复
    - 检查点管理（清理过期）

- **能力探测**
    - 完整性级别检测
    - 特权可用性检查
    - 用户 SID 读取

## 模块结构

```
amberlock-core/src/
├── lib.rs              # 公共导出
├── errors.rs          # 错误定义
├── ops.rs             # 批量上锁/解锁（增强版）
├── recursive.rs       # 递归目录操作
├── progress.rs        # 进度跟踪
├── rollback.rs        # 回滚机制
├── checkpoint.rs      # 断点续执
└── inspect.rs         # 能力探测
```

## 使用示例

### 1. 基础批量上锁

```rust
use amberlock_core::*;
use amberlock_storage::NdjsonWriter;
use std::path::PathBuf;

// 创建日志记录器
let logger = NdjsonWriter::open_append("logs/operations.ndjson")?;

// 配置选项
let opts = BatchOptions {
    desired_level: LabelLevel::High,
    mode: ProtectMode::ReadOnly,
    policy: MandPolicy::NW,
    parallelism: 4,
    dry_run: false,
    enable_rollback: true,
    enable_checkpoint: false,
    idempotent: true,
    stop_on_error: false,
};

// 待锁定的文件
let paths = vec![
    PathBuf::from("C:\\Documents\\secret.txt"),
    PathBuf::from("C:\\Data\\config.json"),
];

// 执行批量上锁
let result = batch_lock(&paths, &opts, &logger, None, None)?;

println!("上锁完成: {}/{} 成功", result.succeeded, result.total);
```

### 2. 带进度回调的上锁

```rust
use std::sync::Arc;

// 创建进度回调
let progress_callback: ProgressCallback = Arc::new(|path, snapshot| {
    println!("[{:.1}%] 正在处理: {}", snapshot.percentage(), path);
    
    if let Some(eta) = snapshot.eta() {
        println!("预计剩余: {:.1}秒", eta.as_secs_f64());
    }
});

let result = batch_lock(
    &paths,
    &opts,
    &logger,
    Some(progress_callback),
    None,
)?;
```

### 3. 递归目录操作

```rust
use std::path::Path;

// 配置递归选项
let recursive_opts = RecursiveOptions {
    desired_level: LabelLevel::High,
    mode: ProtectMode::ReadOnly,
    policy: MandPolicy::NW,
    parallelism: 4,
    follow_symlinks: false,
    stop_on_error: false,
    dry_run: false,
    enable_rollback: true,
};

// 递归上锁整个目录树
let result = recursive_apply_label(
    Path::new("C:\\MyData"),
    &recursive_opts,
    &logger,
    Some(progress_callback),
)?;

println!("递归上锁: {}/{} 成功", result.succeeded, result.total);
```

### 4. 断点续执

```rust
use amberlock_core::checkpoint::CheckpointManager;

// 创建检查点管理器
let checkpoint_manager = CheckpointManager::new("checkpoints")?;

// 启用断点续执
let opts = BatchOptions {
    enable_checkpoint: true,
    ..Default::default()
};

// 执行大规模操作
let result = batch_lock(
    &large_file_list,
    &opts,
    &logger,
    None,
    Some(&checkpoint_manager),
)?;

if let Some(checkpoint_id) = result.checkpoint_id {
    println!("检查点已保存: {}", checkpoint_id);
    
    // 如果操作中断，可以从检查点恢复
    let checkpoint = checkpoint_manager.load(&checkpoint_id)?;
    println!("进度: {:.1}%", checkpoint.percentage());
}
```

### 5. 回滚机制

```rust
use amberlock_core::rollback::RollbackManager;

// 创建回滚管理器（启用自动回滚）
let mut rollback_manager = RollbackManager::new(true);

// 备份对象原始状态
rollback_manager.backup_batch(&paths)?;

// 尝试操作
match risky_operation() {
    Ok(_) => {
        // 成功，提交（禁用自动回滚）
        rollback_manager.commit();
    }
    Err(e) => {
        // 失败，自动回滚（Drop 时触发）
        println!("操作失败: {:?}", e);
    }
}
```

### 6. 能力探测

```rust
// 检查系统能力
let report = probe_capability()?;
let cap = report.capability;

println!("当前完整性级别: {:?}", cap.caller_il);
println!("可访问 SACL: {}", cap.can_touch_sacl);
println!("可设置 System 级: {}", cap.can_set_system);

if !cap.can_touch_sacl {
    eprintln!("警告：缺少 SeSecurityPrivilege，需要管理员权限");
}
```

## 批量操作选项说明

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `desired_level` | `LabelLevel` | `High` | 期望的完整性级别 |
| `mode` | `ProtectMode` | `ReadOnly` | 保护模式（只读/封印） |
| `policy` | `MandPolicy` | `NW` | 强制策略位 |
| `parallelism` | `usize` | `4` | 并发度上限 |
| `dry_run` | `bool` | `false` | 干跑模式（不实际修改） |
| `enable_rollback` | `bool` | `true` | 启用回滚机制 |
| `enable_checkpoint` | `bool` | `false` | 启用断点续执 |
| `idempotent` | `bool` | `true` | 幂等模式 |
| `stop_on_error` | `bool` | `false` | 遇错即停 |

## 递归操作选项说明

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `desired_level` | `LabelLevel` | `High` | 期望的完整性级别 |
| `mode` | `ProtectMode` | `ReadOnly` | 保护模式 |
| `policy` | `MandPolicy` | `NW` | 强制策略位 |
| `parallelism` | `usize` | `4` | 并发度 |
| `follow_symlinks` | `bool` | `false` | 是否跟随符号链接 |
| `stop_on_error` | `bool` | `false` | 遇错即停 |
| `dry_run` | `bool` | `false` | 干跑模式 |
| `enable_rollback` | `bool` | `true` | 启用回滚 |

## 错误处理

所有操作返回 `Result<T, CoreError>`：

```rust
match batch_lock(&paths, &opts, &logger, None, None) {
    Ok(result) => {
        if result.is_success() {
            println!("✅ 全部成功");
        } else if result.is_partial_success() {
            println!("⚠️ 部分成功: {}/{}", result.succeeded, result.total);
        }
    }
    Err(CoreError::AuthFailed) => {
        eprintln!("❌ 密码验证失败");
    }
    Err(CoreError::Cancelled) => {
        eprintln!("⚠️ 操作已取消");
    }
    Err(e) => {
        eprintln!("❌ 操作失败: {:?}", e);
    }
}
```

## 运行示例

```bash
# 运行基础示例（需要管理员权限）
cargo run --example basic_usage

# 运行集成测试
cargo test --test integration_test -- --nocapture
```

## 注意事项

1. **管理员权限**
    - 修改 SACL 需要 `SeSecurityPrivilege`
    - 设置 System 级需要 `SeRelabelPrivilege`
    - 大部分操作需要以管理员身份运行

2. **卷根保护**
    - 对 `C:\` 等卷根仅允许只读模式 + NW 策略
    - 防止系统异常
    - 需要二次确认（由 GUI 层实现）

3. **幂等性**
    - 默认启用，重复上锁不会报错
    - 已存在相同配置的对象会被跳过
    - 可通过 `idempotent: false` 禁用

4. **性能优化**
    - 默认并发度为 4，可根据 CPU 核心数调整
    - 大规模操作建议启用断点续执
    - 干跑模式可用于预览效果

5. **回滚限制**
    - 仅回滚 Mandatory Label（不回滚 DACL/所有者）
    - 失败时自动触发（RAII 模式）
    - 成功后需手动调用 `commit()` 禁用

## 依赖关系

```
amberlock-core
├── amberlock-winsec   # Windows 安全 API
├── amberlock-auth     # 认证模块
├── amberlock-storage  # 日志存储
└── amberlock-types    # 公共类型
```

## 许可证

MIT OR Apache-2.0