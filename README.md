## 总览：交付目标（AI 工具视角）

- **产品名**：AmberLock — 高级文件锁定与数据保护工具
- **平台**：Windows（Vista→11/Server 2008→2025），Rust（MSVC toolchain），Slint GUI
- **关键特性**：
    1. **只读（温和）**：设置对象 Mandatory Label = High + `NW`，阻断中/低 IL 写入/删除；
    2. **封印（强保护）**：优先尝试 **System + `NW`**；若权限不足自动降级 **High + `NW`**，明确记录与提示；
    3. **批量/递归**：单/多文件、目录、卷根（卷根受限与二次确认）；
    4. **轻量 GUI**：Slint 文件浏览器（多选/拖拽）、对象 IL/策略探测、操作面板、轻量日志查看器；
    5. **认证解锁**：Argon2id + DPAPI 本地 vault；
    6. **存储**：**NDJSON** 日志（可流式查看/过滤），Settings.json。
- **不承诺**：无驱动前提下的“完全不可读/隐藏 ACL/属性页看不到 ACL”。
- **安全与合规**：不读取业务内容，仅改写安全描述符；记录操作者 SID、时间、路径、结果。

## 0) 目标 & 约束

- **平台/栈**：Windows（Vista→11/Server 2008→2025），**仅 Windows**；Rust + Slint（轻量 GUI），**无内核驱动**（纯用户态）。
- **功能边界**：
    - 轻量 GUI，包括：设置页 + 轻量文件浏览器（多选、递归预览）+ 轻量日志查看器。
    - **批量**锁定/解锁：单文件、多文件、文件夹、多文件夹、磁盘根目录（谨慎，见风险提示）。
    - 两种模式：**封印/强保护**（尽可能“不可改/不可删”，阅读限制视 OS 机制而定）、**只读模式（温和保护）**。
    - 本地**日志+配置**选 **一种格式**：推荐 **NDJSON（JSON Lines）**，兼顾轻量、易流式展示、结构灵活。
    - **系统托盘**不做，但列入备忘录。
    - 目标：**小而美（lightweight）** & **精而全（完备）**。
- **核心原理现实澄清（非常关键）**
    1. **MIC（Mandatory Integrity Control）确能全局阻止“低完整性主体写高完整性对象”（No-Write-Up）**，在 DAC 之前判定，是实现“温和只读/防误操作”的**核心**。但 **No‑Read‑Up** 的有效范围在官方描述中属于**策略位**，而“默认仅对进程对象使用”的表述常见于内部资料/书籍；对**文件对象的读取限制不可靠**，工程上**不能承诺**“仅通过 MIC 就能完全阻止读取”。因此，“目录/分区级**不可读**/隐藏”若只靠 MIC **不可保证**。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control))
    2. **可用完整性级别**以 **低/中/高/系统** 为主（Untrusted 也存在）。社区资料虽提到“Protected/Secure”级别的 SID（例如 S-1-16-20480），但这更贴近**受保护进程（PPL）体系**而非普通文件标签，且通常**非用户态可随意设置**，不建议作为产品能力承诺。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control?utm_source=chatgpt.com))
    3. **设置/读取 SACL（包含 Mandatory Label）通常需要 `SeSecurityPrivilege`**；将对象标签提升**超过调用者令牌的 IL**，需要 **`SeRelabelPrivilege`**，否则会被判为 **STATUS_INVALID_LABEL/ERROR_PRIVILEGE_NOT_HELD**。你的进程若以“高完整性（管理员提升）”运行，设置为“高”通常可行；设置为“系统”在多数环境需要额外权限，并不总是可行。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo?utm_source=chatgpt.com))
    4. MIC **默认策略位**包含 `NO_WRITE_UP`（普遍生效），`NO_READ_UP`、`NO_EXECUTE_UP` 也定义存在，但其**对象适用性**（特别是“文件对象读”）不应当在产品中作为强保证。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control))

> **实践导向的结论**：
>
> - **只读/防删/防改（对普通/中等完整性进程）**：可通过给对象打**高完整性**标签（并保留 `NW`）稳定实现。
> - **对管理员/高完整性进程**仍可访问：若能设置到**系统完整性**，可把**高完整性**进程也挡在“写”之外（但仍难保“读”）。设置到“系统”需要更高权限，**必须做能力检测与降级**。
> - **完全不可读/隐藏**或**“在安全页看不到 ACL”**这类强目标，\**单靠 MIC + 无驱动\**无法普遍达成；如确需，则作为**可选“增强模式（改 DACL/变更所有者/借助审计）”**单独开关，不作为默认承诺。

------

## 1) 威胁模型 & 使用情景分级

- **主要对手**：误操作、普通恶意软件/脚本（中/低 IL）、浏览器下载的低 IL 内容。
- **不覆盖**（明示）：
    - 本机管理员/具备 `SeTakeOwnership`/`SeDebugPrivilege`/`SeSecurityPrivilege` 的主体**有能力绕过**。
    - 内核态/驱动级对手、PPL 绕过、离线篡改（WinPE 下启动修改 ACL/SDDL）。
- **适配场景**：
    - **只读模式（温和）**：保障可见但不可改（面对绝大多数中/低 IL 进程）。
    - **封印模式（强保护）**：优先尝试**系统 IL（若权限允许）**；否则退化为**高 IL**并提示“对管理员可改/可删”的提示。

------

## 2) 总体架构（模块 & 交互）

```
[Slint GUI]
   ├─ 轻量文件浏览器 (多选/递归预览)
   ├─ 日志查看器 (NDJSON 流式加载/筛选)
   └─ 设置页 (权限自检/模式/并发/日志级别)

[Core Service (Rust, user-mode)]
   ├─ winsec::mic       (MIC 标签读写 / 权限提升 / SDDL)
   ├─ winsec::sid       (SID/SID->字符串/用户SID/进程IL)
   ├─ ops::lock         (批量上锁/递归/回滚/进度)
   ├─ ops::unlock       (解锁/口令校验/降级策略)
   ├─ ops::inspect      (探测对象SD/当前IL/可行策略)
   ├─ storage::ndjson   (日志 & 配置: NDJSON)
   ├─ auth::vault       (本地口令: Argon2id + DPAPI 保护)
   └─ telemetry::audit  (本地操作审计/可选写 Windows 安全日志)
```

- **API/系统调用关键点**：
    - `GetNamedSecurityInfo/SetNamedSecurityInfo`（含 `LABEL_SECURITY_INFORMATION`/`SACL_SECURITY_INFORMATION` 标志）设置/读取强制标签。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfoa?utm_source=chatgpt.com))
    - `AdjustTokenPrivileges` 启用 `SeSecurityPrivilege`（必要时 `SeRelabelPrivilege`），并在操作后关闭。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/sacl-access-right?utm_source=chatgpt.com))
    - 递归应用：可用 `TreeSetNamedSecurityInfo`（带回调、可局部失败回滚/断点续执），或自行遍历。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-treesetnamedsecurityinfow?utm_source=chatgpt.com))
    - 令牌/IL：`GetTokenInformation(TokenIntegrityLevel/TokenUser)`。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control))

------

## 3) 数据与配置建模模板（Rust 结构体草案）

```rust
// 基本枚举
enum TargetKind { File, Directory, VolumeRoot }
enum ProtectMode { ReadOnly, Seal }           // 温和/封印
enum LabelLevel { Medium, High, System }      // 自动降级
bitflags! {
  struct MandPolicy: u32 { const NW = 0x1; const NR = 0x2; const NX = 0x4; }
}

// 上锁记录（日志+配置都使用 NDJSON 一行一条）
#[derive(Serialize, Deserialize)]
struct LockRecord {
  id: String,                    // uuid
  path: String,                  // 规范化绝对路径
  kind: TargetKind,
  mode: ProtectMode,
  level_applied: LabelLevel,     // 实际生效级别（含降级结果）
  policy: MandPolicy,            // 实际策略位（通常 NW）
  time_utc: String,              // ISO8601
  user_sid: String,              // 操作人 SID
  owner_before: Option<String>,  // 变更前信息（便于回滚/诊断）
  sddl_before: Option<String>,
  sddl_after: Option<String>,
  status: String,                // success/partial_fail/...
  errors: Vec<String>,
}

// 配置（同 NDJSON，第一行为 Settings 记录或单独 settings.json）
#[derive(Serialize, Deserialize)]
struct Settings {
  parallelism: usize,            // 并发度上限
  default_mode: ProtectMode,
  default_level: LabelLevel,     // 期望标签级别（High/System）
  enable_nr_nx: bool,            // 仅作为尝试位，不承诺效果
  log_path: String,              // NDJSON 路径
  vault_path: String,            // 口令库 DPAPI 密文文件
  shell_integration: bool,       // 资源管理器右键菜单（后续）
}
```

> **为何选 NDJSON**：顺序可追加、易流式读取、字段可演进且 Slint 侧做表格/筛选极简；比 CSV 更容易承载结构化字段，比 YAML/JSON 文件更适合**长时间追加日志**的轻量实现。

------

## 4) UI 线框（Slint 片段）与交互流

**主窗三分区**：路径选择 + 中央列表视图 + 右侧详情/日志。

- 左：路径选择（文件/文件夹多选），保存收藏夹；
- 中：轻量文件浏览器（当前选定集合的扁平或树形视图），复选框多选；
- 右：
    - “对象详情”：当前对象 IL/SDDL 摘要、可行保护级别（检测结果）；
    - “操作”卡：选择模式（只读/封印）、策略（仅 NW 或尝试 NR/NX）、应用/解锁；
    - “日志”卡：NDJSON 表格 + 关键字/时间过滤。

**Slint 概念片段（示意）：**

```slint
export component MainWindow inherits Window {
  in property <string> status_text;
  callback pick_paths(); // 调用Rust选择文件/文件夹
  callback apply_lock(paths: [string], mode: string);
  callback apply_unlock(paths: [string]);

  VerticalLayout {
    Header { /* 标题+状态栏 */ }
    HorizontalLayout {
      SideBar { /* 收藏夹/预设 */ }
      FileListView { /* 轻量文件浏览器（Rust 提供模型） */ }
      DetailPane {
        ObjectInfo { /* 当前选定对象的IL/策略探测显示 */ }
        ActionPanel { /* 上锁/解锁选项与按钮 */ }
        LogViewer { /* NDJSON 流式加载+过滤 */ }
      }
    }
    Footer { text: status_text; }
  }
}
```

------

## 5) 关键技术要点 & 伪代码

### 5.1 权限与环境自检（启动必做）

- 读取当前进程 **Integrity Level**，检测是否 **High**（已 UAC 提升）。
- 尝试临时启用 `SeSecurityPrivilege`，并探测是否具备 `SeRelabelPrivilege`（如无，则标注“可能无法设置 System 级别”）。
- 若非 High，则 UI 顶部醒目 **“能力受限：仅能设置 High≤IL≤Caller”**。

**伪代码：**

```pseudo
fn preflight() -> Capability {
  token = OpenProcessToken(GetCurrentProcess())
  il = GetTokenInformation(token, TokenIntegrityLevel)
  has_se_security = AdjustTokenPrivileges(token, enable=SE_SECURITY_NAME)
  has_se_relabel  = AdjustTokenPrivileges(token, enable=SE_RELABEL_NAME)

  return Capability {
     caller_il: il, can_set_system: has_se_relabel,
     can_touch_sacl: has_se_security
  }
}
```

> 设置/访问 SACL 需 `SeSecurityPrivilege`；将标签设为高于调用者 IL 需 `SeRelabelPrivilege`。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/sacl-access-right?utm_source=chatgpt.com))

------

### 5.2 构造并写入 SDDL（Mandatory Label）

- **推荐路径**：用 **SDDL** 字符串 + `ConvertStringSecurityDescriptorToSecurityDescriptor` 建立安全描述符，然后 `SetNamedSecurityInfo` 写入 **LABEL_SECURITY_INFORMATION / SACL_SECURITY_INFORMATION**。
- 常用 SDDL 示例：
    - **High + No-Write-Up**：`S:(ML;;NW;;;HI)`
    - **System + No-Write-Up**（若权限允许）：`S:(ML;;NW;;;SI)`
    - （不建议承诺）再叠加 `NR/NX`：`S:(ML;;NWNRNX;;;HI)`（对文件不保证）
- **递归**：`TreeSetNamedSecurityInfo` 可一次性传播；否则自行 DFS 并**并发限流**。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-treesetnamedsecurityinfow?utm_source=chatgpt.com))

**伪代码：**

```pseudo
fn set_integrity_label(path, desired_level, policy /*NW|NR|NX*/) -> Result {
  cap = preflight()
  level = compute_effective_level(desired_level, cap) // System->High 降级
  sddl = format("S:(ML;;{policy};;;{level_to_sddl(level)})")

  sd = ConvertStringSecurityDescriptorToSecurityDescriptor(sddl)
  // 写 Label（实践中对 LABEL_SECURITY_INFORMATION 有实现差异，稳妥起见：
  // 1) 启用 SeSecurityPrivilege；2) 同时带上 SACL_SECURITY_INFORMATION）
  SetNamedSecurityInfoW(
    path, SE_FILE_OBJECT,
    LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
    owner=NULL, group=NULL, dacl=NULL, sacl=sd.Sacl)

  return Ok(level)
}
```

> MIC 的默认策略是 **No-Write-Up**；设计上**优先只设置 NW**确保跨版本稳定。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control))

------

### 5.3 批量/递归与进度回滚

**核心策略**：大集合按**批（batch）**+**并发限流**处理；每个对象独立记录“前后 SDDL”，支持**部分失败**与**幂等重试**。

```pseudo
fn batch_apply(paths[], mode, desired_level) {
  // 计算策略位
  policy = (mode == ReadOnly) ? NW : NW /*+ (NR/NX if user checked, but best-effort) */

  progress = new Progress()
  for_each_concurrent(paths, limit=parallelism) { p =>
     try {
       before = GetNamedSecurityInfo(p, LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)
       applied_level = set_integrity_label(p, desired_level, policy)
       after = GetNamedSecurityInfo(p, ...)
       log_ndjson(LockRecord{..., sddl_before: to_sddl(before), sddl_after: to_sddl(after), level_applied: applied_level})
       progress.ok()
     } catch (e) {
       log_ndjson(LockRecord{..., status:"error", errors:[e.to_string()]})
       progress.fail()
     }
  }
}
```

> 对目录树推荐 `TreeSetNamedSecurityInfoW` + 回调进度（官方支持 SACL/DACL 传播），并为**超大树**提供“**断点续执**（从最后成功条目继续）”。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-treesetnamedsecurityinfow?utm_source=chatgpt.com))

------

### 5.4 解锁与“强认证”实现

> **现实边界**：解锁本质是**修改对象 SACL/Label**。只靠用户态应用**无法防止**有权限的第三方工具（如 icacls/文件属性页/管理员进程）直接修改。因此“强认证”更多是**对我们的 GUI/API 做保护**，而不是绝对系统强制。

- **本地口令实现建议**：
    - 口令→`Argon2id`（含盐+足够内存/时间）→得到 **凭证校验哈希**；
    - 使用 **Windows DPAPI (`CryptProtectData`)** 把包含盐/参数与哈希的“口令卷（vault blob）”**加密存储**到 `vault_path`；解锁时 DPAPI 解密→Argon2 验证→通过则允许执行“移除/降级标签”。
    - 密钥材料内存使用**零化（secure zeroization）**；失败重试**指数退避**；错误**模糊化**（避免计时侧信道）。

**伪代码：**

```pseudo
fn unlock(paths[], password) {
  vault = decrypt_vault_with_dpapi(vault_path)
  if !argon2_verify(vault.hash, password, vault.salt) {
     return Err("auth_failed")
  }
  for p in paths {
     // 移除或降级 Label：
     // 1) 完全移除：清空 ML ACE；2) 或将 IL 复原为 Medium：S:(ML;;NW;;;ME) 亦可
     remove_or_reset_label(p)
     log_ndjson(unlock_record(...))
  }
}
```

------

### 5.5 轻量日志查看器（NDJSON）

- 单文件追加写，行级 JSON：`{time, action, path, result, level_applied, ...}`。
- GUI：分页增量读取（tail 方式），关键字/时间/SID 过滤，导出 CSV。
- 审计可选：引导用户在“本地安全策略→审核对象访问”启用对象访问日志（事件 4670/4663），**非默认**。([dnif.it](https://dnif.it/detecting-windows-security-descriptors-exploitation/?utm_source=chatgpt.com))

------

## 6) 性能优化清单（大规模目录/多盘符）

1. **并发与限流**：IO 绑定，`parallelism = min(8, CPU核心数*2)` 初始；监测 `ERROR_ACCESS_DENIED/SHARING_VIOLATION` 则对该子树降速重试。
2. **首阶段 dry-run**：仅 **GetNamedSecurityInfo** 扫描，计算**需变更数量**与**能否提升到 System**，给出 ETA/风险提示，再执行。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-operations?utm_source=chatgpt.com))
3. **批处理 API**：优先 `TreeSetNamedSecurityInfo`（有进度回调/出错可中止），对超大树分段（按子目录批次）执行。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-treesetnamedsecurityinfow?utm_source=chatgpt.com))
4. **SDDL 缓存**：相同策略/级别的 SD 对象复用，避免重复构造/分配。
5. **异常与回滚**：遇到“正在使用”对象跳过记录；提供**二次扫描**补齐。
6. **日志 IO**：NDJSON 采用**行缓冲**+**定时 flush**；GUI 端使用**窗口化**（仅显示最近 N 条）。

------

## 7) 可靠性与可维护性

- **崩溃安全**：每次实际写入前写一条“预记录（pending）”，成功后标记“done”；重启后清理孤儿记录。
- **断点续执**：记录最后成功 path/时间戳；用户可“从上次失败处继续”。
- **幂等**：同一对象重复设置相同 SDDL 不视为错误。
- **根目录/分区保护警示**：对卷根（如 `C:\`）改 SACL 可能引起**广泛副作用**；UI 强制二次确认，并**只允许只读模式 + High/System（NW）**，禁用 NR/NX “尝试位”。

------

## 8) 关键“不可实现/需降级”的点（透明说明）

- **“属性 → 安全 → 高级”隐藏/不可查看 ACL**：若**不改 DACL/所有者**，无法可靠“隐藏”；可作为**增强模式**：将所有者设为 `TrustedInstaller`，Deny `READ_CONTROL/WRITE_DAC/WRITE_OWNER` 给普通用户（涉及 DACL 改动，不纳入默认）。
- **“完全不可读”**：仅依赖 MIC 不建议承诺；若刚性需求，需**文件内容加密**或**FS 过滤驱动**（超出你当前“无驱动”的约束）。
- **“Protected(5)”级别标签**：不作为文件对象产品能力，保持文档化禁用。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control?utm_source=chatgpt.com))

------

## 9) 具体开发任务分解（Sprint 视图）

**M1：工程骨架（1 周）**

- Rust workspace：`amberlock-gui`（Slint）、`amberlock-core`、`amberlock-winsec`、`amberlock-storage`。
- 引入依赖：`windows`（Win32 API）、`serde/serde_json`、`uuid`、`argon2`、`anyhow`、`thiserror`、`rayon`、`walkdir`。
- `app.manifest`：请求管理员（`requireAdministrator`），高 DPI 设定。

**M2：winsec 基础能力（1–2 周）**

- `Get/SetNamedSecurityInfo` 包装；`AdjustTokenPrivileges`；`GetTokenInformation`。
- SDDL 构造/解析（高/System + NW）与探测（对象当前 IL）。
- 单元测试：临时目录/文件上循环设置/移除。

**M3：批量/递归 & 进度（1 周）**

- `TreeSetNamedSecurityInfo` 封装 + 回调；并发遍历回退实现。
- 幂等/重试/断点续执。

**M4：认证/解锁（1 周）**

- Argon2id + DPAPI 本地 vault；解锁前验证；错误处理。

**M5：GUI（2 周）**

- Slint 主界面/文件浏览器（支持拖投/多选）；
- “对象信息”探测卡（当前 IL/是否可 System）；
- 操作面板（只读/封印切换、并发/策略）；
- 日志查看器：NDJSON 流式 + 过滤导出。

**M6：打包与发布（1 周）**

- 安装包（WiX/Inno Setup/MSIX 任选其一）；首次启动权限自检与提示。

------

## 12) 合规与日志

- **GDPR/等保**：我们仅修改 **安全描述符**，不读取文件敏感内容；记录操作者 SID/时间/对象路径与结果，NDJSON 可审计；可选启用 Windows 审计（事件 4670/4663）。([dnif.it](https://dnif.it/detecting-windows-security-descriptors-exploitation/?utm_source=chatgpt.com))

------

## 13) 打包/运维

- **UAC 清单**：`requireAdministrator`，否则功能降级（只读/High 范围受限）。
- **首启自检**：检测 `SeSecurityPrivilege`、`SeRelabelPrivilege`，展示“System 级封印可用性”。
- **备忘录（未来）**：系统托盘与右键菜单扩展；可在 M7 之后加入。

------

## 14) 已知坑与规避

- **No‑Read‑Up 对文件的实际效果不可依赖**：UI 中将其标注为“尝试/不保证”，默认关闭。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control))
- **将卷根打成 System IL** 可能影响系统更新/某些服务写入：强制二次确认 + 限制仅 `NW`。
- **部分环境设置 System 失败**：缺 `SeRelabelPrivilege`；自动降级为 High 并在日志中记录“降级原因”。([tiraniddo.dev](https://www.tiraniddo.dev/2021/06/the-much-misunderstood.html?utm_source=chatgpt.com))
- **SACL 写入失败（权限/AV 干扰）**：建议在失败时提示“以管理员重试/关闭杀软拦截”并继续处理其他对象。([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo?utm_source=chatgpt.com))

------

## 15) 参考实现/规范（要点出处）

- MIC 机制、默认 `No-Write-Up` 与标签基本事实（官方）：([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control))
- `SYSTEM_MANDATORY_LABEL_ACE` 结构与策略位：([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_mandatory_label_ace?utm_source=chatgpt.com))
- SDDL / ACE 字符串（ML/NW/HI/SI 等）：([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings?utm_source=chatgpt.com))
- 访问/设置 SACL 所需特权、`Set(Security|NamedSecurity)Info`：([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo?utm_source=chatgpt.com))
- 递归传播 API `TreeSetNamedSecurityInfoW`：([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-treesetnamedsecurityinfow?utm_source=chatgpt.com))
- `SeRelabelPrivilege` 与提升标签限制：([tiraniddo.dev](https://www.tiraniddo.dev/2021/06/the-much-misunderstood.html?utm_source=chatgpt.com))
- 完整性级别常见阐述（四级为主；“Protected”不作为常规文件标签）：([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control?utm_source=chatgpt.com))











项目蓝图，包含：**workspace 结构**、**每个 crate 的公开 API 与函数签名**、**Slint 页面完整模板**（含与 Rust 交互的桥接签名）、以及**首批集成测试用例**。所有代码均面向 **Windows + Rust + Slint**，默认纯用户态、无内核驱动，围绕“只读/封印（基于 MIC 的 Mandatory Label）+ 轻量文件浏览器 + 轻量日志查看器 + 本地 NDJSON 存储 + 本地口令认证（Argon2id + DPAPI）”。

------

## 1) Workspace

```
amberlock/
├─ Cargo.toml                 # workspace 清单
├─ amberlock-winsec/          # Windows 安全 API 薄封装（IL/SACL/SDDL）
├─ amberlock-core/            # 业务编排（批量上锁/解锁/递归/回滚/幂等）
├─ amberlock-auth/            # 口令库（Argon2id + DPAPI）
├─ amberlock-storage/         # NDJSON 日志与 Settings
├─ amberlock-gui/             # Slint GUI（文件浏览+日志查看+操作面板）
└─ amberlock-types/           # 公共类型 跨 crate 约定
```

## 3) `amberlock-winsec`（Windows 安全 API 薄封装）

**职责**：

- 读取当前进程 IL、启用/禁用特权（`SeSecurityPrivilege`、`SeRelabelPrivilege`）。
- 读取/设置对象 SACL 中的 Mandatory Label（以 SDDL/ACE 形式）。
- 递归施加（优先 `TreeSetNamedSecurityInfoW`；不可用时回退 DFS）。

> 实现细节：
>
> - `set_mandatory_label` 内部：启用 `SeSecurityPrivilege`（必要），尝试 `SeRelabelPrivilege`（若目标级别为 System），`SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, …)`。
> - `tree_apply_label`：若可用，优先 `TreeSetNamedSecurityInfoW`；否则 WalkDir + Rayon 并发受 `opts.parallelism` 限制。
> - 所有 Win32 调用封装 `Result<T>`，将 `GetLastError()` 转 `WinSecError::Win32`。

------

## 4) `amberlock-auth`（本地口令库：Argon2id + DPAPI）

**职责**：

- `vault.json`（或二进制 blob）中保存盐/参数/哈希，整体由 **DPAPI** 保护（当前用户/本机）。
- 校验时：DPAPI 解密 → Argon2id 验证 → 常数时间比较/指数退避。

## 5) `amberlock-storage`（NDJSON 日志 + Settings）

**职责**：

- 以 **NDJSON** 逐行追加 `LockRecord`/`UnlockRecord`/`SystemEvent`。
- 读取：按偏移量/行数分页；过滤：时间区间/关键字/状态。
- Settings：一个简易 JSON 文件（或 NDJSON 第一条记录为 `Settings`）。

## 7) `amberlock-gui`（Slint 页面完整模板 + Rust 桥接）

### 7.1 Slint 页面模板（`ui/main.slint`）

> 包含：头部状态栏、左侧收藏/路径选择、中间轻量文件浏览列表、右侧对象信息/操作面板/日志查看器、底部状态文本。
> 与 Rust 交互通过回调/属性：`pick_paths()`, `apply_lock(paths, mode, level, nr_nx)`, `apply_unlock(paths, password)`，`filter_logs(query)` 等。

## 8) `amberlock-telemetry`（可选）

- 提供 `emit_event(source, id, message)`；或仅将统计输出到 NDJSON。此处略，待 M7 引入。

------

## 9) `amberlock-fixtures`（测试夹具）

提供创建临时目录树、随机文件、拥塞/占用文件模拟（可选）。

------

## 11) 关键实现提示（落地细节）

- **特权**：`set_mandatory_label` 内部务必先 `enable_privilege(SeSecurity, true)`；若目标级别为 `System`，尝试 `enable_privilege(SeRelabel, true)`；完成后**恢复**（关闭）。
- **SDDL 构造**：构造 `"S:(ML;;NW;;;HI)"` 等字符串后，使用 `ConvertStringSecurityDescriptorToSecurityDescriptorW` 获取 SACL；调用 `SetNamedSecurityInfoW` 指定 `LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION`。
- **递归**：`TreeSetNamedSecurityInfoW` 可在目录上传播 ML ACE；如遇不支持或需要细粒度控制，回退 WalkDir + 并发。
- **NR/NX**：UI 中明确“尝试/不保证”；默认仅 `NW`。
- **日志**：每个对象写两段记录也可（`pending` → `done`），用于崩溃恢复；上文示例为精简单条记录。
- **灰度/降级**：当 `SeRelabel` 不可用时，将 `desired_level=System` 自动降为 `High`，并在 `LockRecord.status` 添加 `"downgraded:System->High"` 提示。
- **卷根保护**：对 `C:\` 等路径做双重确认并限制为 `NW`；强烈不建议勾选 `NR/NX`。

------

## 12) 构建与运行（要点）

- **清单文件**：在 GUI 项目 `app.manifest` 设为 `requireAdministrator`（或给出“功能降级”提示）。
- **运行**：管理员启动 GUI；非管理员启动则 UI 顶部显示“能力受限”状态。

------

## 13) 后续扩展（Backlog 简述）

- 资源管理器右键菜单（Shell 扩展）与系统托盘（可选）。
- 事件日志/遥测（`amberlock-telemetry`）。
- “增强模式”（可选开关）：改 DACL/所有者（`TrustedInstaller`）以**更强抑制** ACL 修改——默认关闭且强警告。
- 文件浏览器：加入懒加载与 IL 批量探测列。
- “断点续执”：记录最后成功项并提供“继续”按钮。
- `amberlock-telemetry`
    - 提供 `emit_event(source, id, message)`；或仅将统计输出到 NDJSON。此处略，待 M7 引入。
- `amberlock-fixtures` 测试夹具

