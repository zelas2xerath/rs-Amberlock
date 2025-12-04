# amberlock-winsec

**Windows 安全 API 薄封装 - AmberLock 核心模块**

本 crate 提供对 Windows 强制完整性控制（Mandatory Integrity Control, MIC）的 Rust 封装，是 AmberLock 项目的核心安全基础设施。

---

## 📋 功能概览

### ✅ 已实现功能

1. **令牌操作 (`token.rs`)**
   - ✅ 读取进程完整性级别（Medium/High/System）
   - ✅ 启用/禁用特权（SeSecurityPrivilege, SeRelabelPrivilege）
   - ✅ 读取用户 SID
   - ✅ 系统能力探测（自动检测可用权限）

2. **SDDL 操作 (`sddl.rs`)**
   - ✅ 将 LabelLevel 映射到 SDDL 标记（ME/HI/SI）
   - ✅ 构造 Mandatory Label SDDL 段（如 "S:(ML;;NW;;;HI)"）
   - ✅ 从对象读取 SACL 中的 ML
   - ✅ 清除对象的 ML

3. **标签设置 (`setlabel.rs`)**
   - ✅ 设置对象的强制完整性标签
   - ✅ 移除对象的标签
   - ✅ 读取对象当前标签
   - ✅ 自动降级逻辑（System → High）

4. **目录树操作 (`treeops.rs`)**
   - ✅ 递归应用标签到整个目录树
   - ✅ 并发处理（基于 rayon）
   - ✅ 进度回调支持
   - ✅ 错误处理与跳过策略

5. **错误处理 (`error.rs`)**
   - ✅ 统一的错误类型（WinSecError）
   - ✅ Win32 错误码映射
   - ✅ 特权缺失检测

---

## 🎯 核心 API

### 1. 能力探测（启动前自检）

```rust
use amberlock_winsec::*;

let cap = probe_capability()?;
println!("完整性级别: {:?}", cap.caller_il);
println!("SeSecurityPrivilege: {}", cap.has_se_security);
println!("SeRelabelPrivilege: {}", cap.has_se_relabel);

// 根据能力决定可设置的最高级别
let effective_level = compute_effective_level(
    LabelLevel::System,
    cap.has_se_relabel
);
```

### 2. 设置单个文件/目录的标签

```rust
// 设置为 High + No-Write-Up
set_mandatory_label(
    "C:\\test\\file.txt",
    LabelLevel::High,
    MandPolicy::NW
)?;

// 读取当前标签
let label = get_object_label("C:\\test\\file.txt")?;
println!("级别: {:?}, 策略: {:?}", label.level, label.policy);

// 移除标签（恢复默认）
remove_mandatory_label("C:\\test\\file.txt")?;
```

### 3. 递归目录树操作

```rust
let opts = TreeOptions {
    parallelism: 4,
    follow_symlinks: false,
    desired_level: LabelLevel::High,
    policy: MandPolicy::NW,
    stop_on_error: false,
};

// 应用标签到整个树
let stats = tree_apply_label(
    "C:\\test\\directory",
    &opts,
    |current, path, success| {
        println!("[{}/total] {} - {}", current, path, success);
    }
)?;

println!("成功: {}, 失败: {}", stats.succeeded, stats.failed);
```

### 4. 特权管理

```rust
// 启用必需特权
enable_privilege(Privilege::SeSecurity, true)?;

// ... 执行需要特权的操作 ...

// 恢复特权状态
enable_privilege(Privilege::SeSecurity, false)?;
```

---

## 🔒 完整性级别与策略

### 完整性级别（Integrity Levels）

| 级别 | SDDL | SID | 用途 |
|------|------|-----|------|
| **Medium** | ME | S-1-16-0x2000 | 标准用户进程（UAC 启用时） |
| **High** | HI | S-1-16-0x3000 | 管理员提升进程 |
| **System** | SI | S-1-16-0x4000 | 系统服务和内核级进程 |

### 强制策略（Mandatory Policies）

| 策略 | 位标志 | 适用对象 | 说明 |
|------|--------|---------|------|
| **NW** (No-Write-Up) | 0x1 | 所有对象 | ✅ **可靠**：低 IL 进程无法写入高 IL 对象 |
| **NR** (No-Read-Up) | 0x2 | 进程对象 | ⚠️ **不保证**：对文件对象不可靠 |
| **NX** (No-Execute-Up) | 0x4 | 可执行文件 | ⚠️ **不保证**：对普通文件不可靠 |

**推荐实践**：仅使用 `MandPolicy::NW`，确保跨版本稳定性。

---

## 🛡️ 安全注意事项

### 1. 权限要求

- **必需**：`SeSecurityPrivilege` - 修改 SACL
- **可选**：`SeRelabelPrivilege` - 设置 System 级标签

### 2. 自动降级

```rust
// 若无 SeRelabelPrivilege，System 自动降为 High
let effective = compute_effective_level(LabelLevel::System, false);
assert_eq!(effective, LabelLevel::High);
```

### 3. 不可绕过性声明

本 crate 提供的保护**无法防御**：
- 本机管理员/具备 `SeTakeOwnership` 的主体
- 内核态/驱动级对手
- 离线篡改（WinPE 下修改 ACL）

适用场景：
- ✅ 防止普通用户误操作
- ✅ 防止恶意软件/脚本（中/低 IL）
- ❌ 防止管理员级别攻击

---

## 🧪 测试

### 单元测试

```bash
cargo test --lib
```

### 集成测试（需要管理员权限）

```powershell
# 以管理员身份运行 PowerShell
cargo test --test integration -- --nocapture
```

### 测试覆盖

- ✅ 单文件标签生命周期
- ✅ 目录树递归操作
- ✅ 策略组合验证
- ✅ 自动降级逻辑
- ✅ 错误处理

---

## 📚 技术参考

### Windows API 调用链

```
用户代码
  ↓ set_mandatory_label()
  ↓ enable_privilege(SeSecurity)
  ↓ build_ml_sddl() → "S:(ML;;NW;;;HI)"
  ↓ ConvertStringSecurityDescriptorToSecurityDescriptorW
  ↓ SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)
系统内核
  ↓ 安全引用监视器（SRM）
  ↓ 写入对象 SACL
```

### 关键 Windows API

| API | 用途 | 头文件 |
|-----|------|--------|
| `GetTokenInformation` | 读取令牌信息（IL/SID） | `securitybaseapi.h` |
| `AdjustTokenPrivileges` | 启用/禁用特权 | `securitybaseapi.h` |
| `SetNamedSecurityInfoW` | 设置对象安全描述符 | `aclapi.h` |
| `GetNamedSecurityInfoW` | 读取对象安全描述符 | `aclapi.h` |
| `ConvertStringSecurityDescriptorToSecurityDescriptorW` | SDDL → SD | `sddl.h` |

---

## 🔧 依赖项

```toml
[dependencies]
windows = { version = "0.62", features = [
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_System_Threading",
    # ...
]}
bitflags = "2.10"
rayon = "1.11"
walkdir = "2.5"
anyhow = "1.0"
thiserror = "2.0"
```

---

## 📖 示例：只读保护

```rust
use amberlock_winsec::*;

fn protect_readonly(path: &str) -> anyhow::Result<()> {
    // 1. 检查能力
    let cap = probe_capability()?;
    if !cap.has_se_security {
        anyhow::bail!("需要 SeSecurityPrivilege");
    }

    // 2. 设置为 High + NW（防止中/低 IL 写入）
    set_mandatory_label(path, LabelLevel::High, MandPolicy::NW)?;

    // 3. 验证
    let label = get_object_label(path)?;
    assert_eq!(label.level, LabelLevel::High);

    println!("✅ {} 已设置为只读保护", path);
    Ok(())
}
```

---

## 🐛 已知问题与限制

1. **NR/NX 对文件不保证**
   - Windows 官方文档明确 NR 主要用于进程对象
   - 建议仅使用 NW 策略

2. **卷根保护风险**
   - 对 `C:\` 等卷根设置 System IL 可能影响系统更新
   - 需强制二次确认

3. **跨版本兼容性**
   - 测试覆盖 Windows Vista → Windows 11
   - Windows Server 2008 → 2025

---

## 🤝 贡献指南

1. 所有新增 API 必须包含：
   - 详细的文档注释（含示例）
   - 单元测试
   - 集成测试（如需管理员权限，标注 `#[ignore]`）

2. 遵循错误处理约定：
   - 使用 `Result<T>` 返回类型
   - 通过 `WinSecError` 包装 Win32 错误码

3. 性能优化建议：
   - 对目录树操作使用并发（rayon）
   - 避免重复启用/禁用特权

---

## 📄 许可证

MIT OR Apache-2.0

---

## 🔗 相关资源

- [Microsoft: Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Windows Internals, 7th Edition - Chapter 7](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [MSDN: Security Descriptor String Format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)

---

**维护者**: Zelas2Xerath  
**版本**: 0.1.0  
**最后更新**: 2025-01-01