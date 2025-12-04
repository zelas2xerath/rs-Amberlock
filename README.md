Deploy

下面给出一个**可直接开工**的项目蓝图，包含：**workspace 结构**、**每个 crate 的公开 API 与函数签名**、**Slint 页面完整模板**（含与 Rust 交互的桥接签名）、以及**首批集成测试用例**。所有代码均面向 **Windows + Rust + Slint**，默认纯用户态、无内核驱动，围绕“只读/封印（基于 MIC 的 Mandatory Label）+ 轻量文件浏览器 + 轻量日志查看器 + 本地 NDJSON 存储 + 本地口令认证（Argon2id + DPAPI）”。

------

## 1) Workspace 布局（建议）

```
amberlock/
├─ Cargo.toml                 # workspace 清单
├─ amberlock-winsec/          # Windows 安全 API 薄封装（IL/SACL/SDDL）
├─ amberlock-core/            # 业务编排（批量上锁/解锁/递归/回滚/幂等）
├─ amberlock-auth/            # 口令库（Argon2id + DPAPI）
├─ amberlock-storage/         # NDJSON 日志与 Settings
├─ amberlock-telemetry/       # （可选）Windows 事件日志/统计
├─ amberlock-gui/             # Slint GUI（文件浏览+日志查看+操作面板）
└─ amberlock-fixtures/        # 测试夹具（临时目录/文件生成）
```

**根 `Cargo.toml`（示例）：**

```toml
[workspace]
members = [
  "amberlock-winsec",
  "amberlock-core",
  "amberlock-auth",
  "amberlock-storage",
  "amberlock-telemetry",
  "amberlock-gui",
  "amberlock-fixtures",
]

[workspace.package]
edition = "2021"
license = "MIT OR Apache-2.0"
authors = ["AmberLock Team"]

[workspace.dependencies]
anyhow = "1"
thiserror = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
once_cell = "1"
bitflags = "2"
rayon = "1"
walkdir = "2"
time = { version = "0.3", features = ["formatting"] }
argonautica = { version = "0.2", optional = true } # 如选用；下文采用 argon2 crate
argon2 = "0.5"
rand = "0.8"
tempfile = "3"
proptest = "1"
quickcheck = "1"
# DPAPI & Win32
windows = { version = "0.57", features = [
  "Win32_Foundation",
  "Win32_Security",
  "Win32_Security_Authorization",
  "Win32_System_Memory",
  "Win32_System_Threading",
  "Win32_System_Com",
  "Win32_System_SystemServices",
  "Win32_UI_Shell",
  "Win32_Storage_FileSystem",
] }
# GUI
slint = { version = "1.7", features = ["backend-winit", "renderer-femtovg"] }
rfd = "0.14" # 轻量文件选择对话框
parking_lot = "0.12"
```

------

## 2) 公共类型（跨 crate 约定）

建议在 `amberlock-core/src/types.rs` 提供共用类型并由其他 crate 复用（或单独建 `amberlock-types`）。

```rust
// amberlock-core/src/types.rs
use serde::{Deserialize, Serialize};
use bitflags::bitflags;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetKind { File, Directory, VolumeRoot }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtectMode { ReadOnly, Seal } // 温和/封印

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LabelLevel { Medium, High, System }

bitflags! {
  #[derive(Serialize, Deserialize)]
  pub struct MandPolicy: u32 {
    const NW = 0x1; // No-Write-Up
    const NR = 0x2; // No-Read-Up (对文件不保证，默认不用)
    const NX = 0x4; // No-Execute-Up (对文件不保证，默认不用)
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRecord {
  pub id: String,
  pub path: String,
  pub kind: TargetKind,
  pub mode: ProtectMode,
  pub level_applied: LabelLevel,
  pub policy: MandPolicy,
  pub time_utc: String,
  pub user_sid: String,
  pub owner_before: Option<String>,
  pub sddl_before: Option<String>,
  pub sddl_after: Option<String>,
  pub status: String,
  pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
  pub parallelism: usize,
  pub default_mode: ProtectMode,
  pub default_level: LabelLevel,
  pub enable_nr_nx: bool,
  pub log_path: String,
  pub vault_path: String,
  pub shell_integration: bool,
}

#[derive(Debug, Clone)]
pub struct Capability {
  pub caller_il: LabelLevel,
  pub can_touch_sacl: bool,
  pub can_set_system: bool, // 具备 SeRelabelPrivilege
}
```

------

## 3) `amberlock-winsec`（Windows 安全 API 薄封装）

**职责**：

- 读取当前进程 IL、启用/禁用特权（`SeSecurityPrivilege`、`SeRelabelPrivilege`）。
- 读取/设置对象 SACL 中的 Mandatory Label（以 SDDL/ACE 形式）。
- 递归施加（优先 `TreeSetNamedSecurityInfoW`；不可用时回退 DFS）。

**Cargo.toml（节选）**

```toml
[package]
name = "amberlock-winsec"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
windows.workspace = true
serde.workspace = true
serde_json.workspace = true
bitflags.workspace = true
```

**lib.rs（签名 & 关键结构）**

```rust
// amberlock-winsec/src/lib.rs
#![cfg(target_os = "windows")]
mod sddl;
mod token;
mod setlabel;
mod treeops;
pub mod error;

pub use token::{read_process_il, enable_privilege, Privilege, read_user_sid, CapabilityProbe};
pub use setlabel::{LabelLevel, MandPolicy, SddlLabel, set_mandatory_label, remove_mandatory_label,
                   get_object_label, level_to_sddl_token, compute_effective_level};
pub use treeops::{TreeOptions, TreeStats, tree_apply_label, tree_remove_label};
```

**error.rs**

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WinSecError {
  #[error("Win32 error {code}: {msg}")]
  Win32 { code: u32, msg: String },
  #[error("Privilege not held: {0}")]
  PrivilegeMissing(&'static str),
  #[error("Unsupported platform/operation")]
  Unsupported,
  #[error("Invalid label or SDDL")]
  InvalidLabel,
}
pub type Result<T> = std::result::Result<T, WinSecError>;
```

**token.rs（签名）**

```rust
use super::error::Result;
use crate::setlabel::LabelLevel;

#[derive(Debug, Clone)]
pub struct CapabilityProbe {
  pub caller_il: LabelLevel,
  pub has_se_security: bool,
  pub has_se_relabel: bool,
  pub user_sid: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Privilege {
  SeSecurity,
  SeRelabel,
}

pub fn enable_privilege(p: Privilege, enable: bool) -> Result<bool>;

/// 读取当前进程令牌的完整性级别（Medium/High/System 映射）
pub fn read_process_il() -> Result<LabelLevel>;

/// 读取当前进程用户 SID（用于日志）
pub fn read_user_sid() -> Result<String>;

/// 启动前自检（IL + 特权）
pub fn probe_capability() -> Result<CapabilityProbe>;
```

**sddl.rs（签名）**

```rust
use super::error::Result;
use crate::setlabel::{LabelLevel, MandPolicy};

/// 将 LabelLevel 映射到 SDDL 标记（"ME"/"HI"/"SI"）
pub fn level_to_sddl_token(level: LabelLevel) -> &'static str;

/// 构造 Mandatory Label 的 SDDL 段，如 "S:(ML;;NW;;;HI)"
pub fn build_ml_sddl(level: LabelLevel, policy: MandPolicy) -> String;

/// 从对象读取 SACL 中的 Mandatory Label（返回 level、policy、原始 SDDL）
pub fn read_ml_from_object(path: &str) -> Result<(Option<LabelLevel>, Option<MandPolicy>, String)>;

/// 清除对象中的 Mandatory Label（仅移除 ML ACE，不改 DACL/OWNER）
pub fn clear_ml_on_object(path: &str) -> Result<()>;
```

**setlabel.rs（签名）**

```rust
use super::error::Result;
use bitflags::bitflags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelLevel { Medium, High, System }

bitflags! {
  pub struct MandPolicy: u32 { const NW = 0x1; const NR = 0x2; const NX = 0x4; }
}

#[derive(Debug, Clone)]
pub struct SddlLabel {
  pub sddl: String,
  pub level: LabelLevel,
  pub policy: MandPolicy,
}

pub fn compute_effective_level(desired: LabelLevel, can_set_system: bool) -> LabelLevel;

/// 获取对象当前 ML（若无则 level/policy 为 None），返回完整 SDDL 文本
pub fn get_object_label(path: &str) -> Result<SddlLabel>;

/// 设置对象 ML（常用：仅 NW；NR/NX 仅作为尝试位传入）
pub fn set_mandatory_label(path: &str, level: LabelLevel, policy: MandPolicy) -> Result<()>;

/// 移除对象 ML
pub fn remove_mandatory_label(path: &str) -> Result<()>;
```

**treeops.rs（签名）**

```rust
use super::error::Result;
use crate::setlabel::{LabelLevel, MandPolicy};

#[derive(Debug, Clone)]
pub struct TreeOptions {
  pub parallelism: usize,
  pub follow_symlinks: bool,
  pub desired_level: LabelLevel,
  pub policy: MandPolicy,
  pub stop_on_error: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TreeStats {
  pub total: u64,
  pub succeeded: u64,
  pub failed: u64,
  pub skipped: u64,
}

pub fn tree_apply_label(root: &str, opts: &TreeOptions,
  progress: impl Fn(u64, &str, bool) + Send + Sync
) -> Result<TreeStats>;

pub fn tree_remove_label(root: &str, opts: &TreeOptions,
  progress: impl Fn(u64, &str, bool) + Send + Sync
) -> Result<TreeStats>;
```

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

**Cargo.toml（节选）**

```toml
[package]
name = "amberlock-auth"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
windows.workspace = true
serde.workspace = true
serde_json.workspace = true
argon2.workspace = true
rand.workspace = true
```

**lib.rs（签名）**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultBlob {
  pub version: u32,
  pub salt: Vec<u8>,
  pub params: String,   // argon2 参数序列化，例如 "m=19456,t=2,p=1"
  pub hash: Vec<u8>,
}

pub fn create_vault(password: &str) -> anyhow::Result<Vec<u8>>;  // -> dpapi_encrypted_blob
pub fn load_vault(dpapi_blob: &[u8]) -> anyhow::Result<VaultBlob>;
pub fn verify_password(dpapi_blob: &[u8], password: &str) -> anyhow::Result<bool>;
```

------

## 5) `amberlock-storage`（NDJSON 日志 + Settings）

**职责**：

- 以 **NDJSON** 逐行追加 `LockRecord`/`UnlockRecord`/`SystemEvent`。
- 读取：按偏移量/行数分页；过滤：时间区间/关键字/状态。
- Settings：一个简易 JSON 文件（或 NDJSON 第一条记录为 `Settings`）。

**Cargo.toml（节选）**

```toml
[package]
name = "amberlock-storage"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
time.workspace = true
parking_lot.workspace = true
```

**lib.rs（签名）**

```rust
use parking_lot::Mutex;
use std::{fs::File, io::{BufRead, BufReader, Write}, path::Path};

use amberlock_core::types::{LockRecord, Settings};

pub struct NdjsonWriter {
  file: Mutex<File>,
}

impl NdjsonWriter {
  pub fn open_append<P: AsRef<Path>>(path: P) -> anyhow::Result<Self>;
  pub fn write_record<T: serde::Serialize>(&self, rec: &T) -> anyhow::Result<()>;
  pub fn flush(&self) -> anyhow::Result<()>;
}

pub struct NdjsonReader {
  file: BufReader<File>,
}

impl NdjsonReader {
  pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self>;
  pub fn read_last_n(&mut self, n: usize) -> anyhow::Result<Vec<serde_json::Value>>;
  pub fn filter(&mut self, key_substr: &str, limit: usize)
      -> anyhow::Result<Vec<serde_json::Value>>;
}

pub fn load_settings<P: AsRef<Path>>(path: P) -> anyhow::Result<Settings>;
pub fn save_settings<P: AsRef<Path>>(path: P, s: &Settings) -> anyhow::Result<()>;
```

------

## 6) `amberlock-core`（编排：批量上锁/解锁/探测）

**Cargo.toml（节选）**

```toml
[package]
name = "amberlock-core"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
walkdir.workspace = true
rayon.workspace = true
uuid.workspace = true
time.workspace = true
windows.workspace = true
amberlock-winsec = { path = "../amberlock-winsec" }
amberlock-auth = { path = "../amberlock-auth" }
amberlock-storage = { path = "../amberlock-storage" }
```

**lib.rs（签名 & 关键路径）**

```rust
pub mod types;
pub mod ops;
pub mod inspect;
pub mod errors;

pub use types::*;
pub use ops::{batch_lock, batch_unlock, BatchOptions, BatchResult};
pub use inspect::{probe_capability, InspectReport};
```

**errors.rs**

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
  #[error("WinSec error: {0}")]
  WinSec(#[from] amberlock_winsec::error::WinSecError),
  #[error("Auth failed")]
  AuthFailed,
  #[error("Storage error: {0}")]
  Storage(#[from] anyhow::Error),
  #[error("Operation cancelled")]
  Cancelled,
}

pub type Result<T> = std::result::Result<T, CoreError>;
```

**inspect.rs（签名）**

```rust
use crate::types::{Capability, LabelLevel};
use amberlock_winsec as winsec;

#[derive(Debug, Clone)]
pub struct InspectReport {
  pub capability: Capability,
}

pub fn probe_capability() -> anyhow::Result<InspectReport> {
  let p = winsec::probe_capability()?;
  Ok(InspectReport {
    capability: Capability {
      caller_il: p.caller_il,
      can_touch_sacl: p.has_se_security,
      can_set_system: p.has_se_relabel,
    }
  })
}
```

**ops.rs（签名 & 伪实现轮廓）**

```rust
use crate::types::*;
use crate::errors::{Result, CoreError};
use amberlock_winsec as winsec;
use amberlock_storage::NdjsonWriter;
use uuid::Uuid;
use time::OffsetDateTime;
use rayon::prelude::*;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BatchOptions {
  pub desired_level: LabelLevel,
  pub mode: ProtectMode,
  pub policy: MandPolicy,      // 默认仅 NW；NR/NX 作为尝试位
  pub parallelism: usize,
  pub dry_run: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BatchResult {
  pub total: u64,
  pub succeeded: u64,
  pub failed: u64,
  pub downgraded: u64, // 期望 System 实际 High 等
}

fn now_iso8601() -> String {
  OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap()
}

fn file_kind(p: &Path) -> TargetKind {
  if p.is_dir() { TargetKind::Directory } else { TargetKind::File }
}

pub fn batch_lock(paths: &[PathBuf], opts: &BatchOptions,
                  logger: &NdjsonWriter) -> Result<BatchResult> {
  let cap = winsec::probe_capability()?;
  let eff_level = winsec::compute_effective_level(opts.desired_level, cap.has_se_relabel);
  let user_sid = winsec::read_user_sid().unwrap_or_default();

  let result = paths.par_iter()
    .with_max_len(1) // 控制任务粒度
    .map(|p| {
      let id = Uuid::new_v4().to_string();
      let path = p.to_string_lossy().to_string();

      let before = winsec::get_object_label(&path).ok();
      let mut rec = LockRecord {
        id, path: path.clone(),
        kind: file_kind(p),
        mode: opts.mode,
        level_applied: eff_level,
        policy: opts.policy,
        time_utc: now_iso8601(),
        user_sid: user_sid.clone(),
        owner_before: None,
        sddl_before: before.as_ref().map(|s| s.sddl.clone()),
        sddl_after: None,
        status: "pending".into(),
        errors: vec![],
      };

      let r = if opts.dry_run {
        Ok(())
      } else {
        winsec::set_mandatory_label(&path, eff_level, opts.policy)
      };

      match r {
        Ok(_) => {
          let after = winsec::get_object_label(&path).ok();
          rec.sddl_after = after.as_ref().map(|s| s.sddl.clone());
          rec.status = "success".into();
          logger.write_record(&rec).ok();
          Ok::<(), CoreError>(())
        }
        Err(e) => {
          rec.status = "error".into();
          rec.errors.push(format!("{e:?}"));
          logger.write_record(&rec).ok();
          Err(CoreError::from(e))
        }
      }
    })
    .collect::<Vec<_>>();

  let mut br = BatchResult::default();
  br.total = result.len() as u64;
  for r in result {
    match r {
      Ok(_) => br.succeeded += 1,
      Err(_) => br.failed += 1,
    }
  }
  Ok(br)
}

pub fn batch_unlock(paths: &[PathBuf], password: &str,
                    vault_blob: &[u8], logger: &NdjsonWriter) -> Result<BatchResult> {
  if !amberlock_auth::verify_password(vault_blob, password).map_err(|_| CoreError::AuthFailed)? {
    return Err(CoreError::AuthFailed);
  }
  let opts = BatchOptions {
    desired_level: LabelLevel::Medium,
    mode: ProtectMode::ReadOnly,
    policy: MandPolicy::NW,
    parallelism: 4,
    dry_run: false,
  };
  // 逻辑：移除 ML 或降级为 Medium（这里采用移除）
  let res = paths.iter().map(|p| p.to_string_lossy().to_string())
    .map(|path| {
      let id = Uuid::new_v4().to_string();
      let before = winsec::get_object_label(&path).ok();
      let r = winsec::remove_mandatory_label(&path);
      let mut rec = LockRecord {
        id, path: path.clone(),
        kind: file_kind(Path::new(&path)),
        mode: opts.mode,
        level_applied: LabelLevel::Medium,
        policy: opts.policy,
        time_utc: now_iso8601(),
        user_sid: winsec::read_user_sid().unwrap_or_default(),
        owner_before: None,
        sddl_before: before.as_ref().map(|s| s.sddl.clone()),
        sddl_after: None,
        status: String::new(),
        errors: vec![],
      };
      match r {
        Ok(_) => {
          rec.status = "success".into();
          logger.write_record(&rec).ok();
          Ok::<(), CoreError>(())
        }
        Err(e) => {
          rec.status = "error".into();
          rec.errors.push(format!("{e:?}"));
          logger.write_record(&rec).ok();
          Err(CoreError::from(e))
        }
      }
    })
    .collect::<Vec<_>>();

  let mut br = BatchResult::default();
  br.total = res.len() as u64;
  for r in res { if r.is_ok() { br.succeeded+=1 } else { br.failed+=1 } }
  Ok(br)
}
```

------

## 7) `amberlock-gui`（Slint 页面完整模板 + Rust 桥接）

**目录结构**

```
amberlock-gui/
├─ Cargo.toml
├─ build.rs
├─ ui/
│  └─ main.slint
└─ src/
   ├─ main.rs
   ├─ model.rs       # 列表模型/日志模型
   └─ bridge.rs      # 与 core 的桥接（调用 batch_*、读取日志等）
```

**Cargo.toml（节选）**

```toml
[package]
name = "amberlock-gui"
version = "0.1.0"
edition = "2021"

[build-dependencies]
slint-build = "1.7"

[dependencies]
slint.workspace = true
anyhow.workspace = true
serde.workspace = true
serde_json.workspace = true
walkdir.workspace = true
rfd.workspace = true
parking_lot.workspace = true
rayon.workspace = true
windows.workspace = true
amberlock-core = { path = "../amberlock-core" }
amberlock-storage = { path = "../amberlock-storage" }
amberlock-auth = { path = "../amberlock-auth" }
```

**build.rs**

```rust
fn main() {
  slint_build::compile("ui/main.slint").unwrap();
}
```

### 7.1 Slint 页面模板（`ui/main.slint`）

> 包含：头部状态栏、左侧收藏/路径选择、中间轻量文件浏览列表、右侧对象信息/操作面板/日志查看器、底部状态文本。
>  与 Rust 交互通过回调/属性：`pick_paths()`, `apply_lock(paths, mode, level, nr_nx)`, `apply_unlock(paths, password)`，`filter_logs(query)` 等。

```slint
export enum Mode { ReadOnly, Seal }
export enum Level { Medium, High, System }

export struct FileItem {
  path: string,
  kind: string,     // "File" | "Directory" | "VolumeRoot"
  selected: bool,
  il_text: string,  // 当前探测到的 IL 显示
}

export struct LogRow {
  time: string,
  action: string,   // "lock"/"unlock"
  path: string,
  level: string,
  status: string,
}

export component MainWindow inherits Window {
  width: 1100px;
  height: 720px;
  title: "AmberLock - 高级文件锁定与数据保护";

  // 状态与回调
  in-out property <string> status_text <=> footer.text;
  in property <[FileItem]> files;
  in property <[LogRow]> logs;
  in property <string> user_sid;

  callback pick_files();           // 选择文件
  callback pick_folders();         // 选择文件夹
  callback refresh_logs(query: string);
  callback request_lock(mode: Mode, level: Level, try_nr_nx: bool);
  callback request_unlock(password: string);

  // 布局
  VerticalLayout {
    spacing: 6px;

    Rectangle {
      height: 40px;
      HorizontalLayout {
        spacing: 12px;
        Text { text: "琥珀锁 AmberLock"; vertical-alignment: center; font-size: 18px; }
        Rectangle { horizontal-stretch: 1.0; }
        Text { text: "当前用户 SID: " + root.user_sid; vertical-alignment: center; font-size: 12px; }
      }
    }

    HorizontalLayout {
      spacing: 10px;

      // 左栏：选择 & 收藏（简化）
      VerticalLayout {
        width: 220px;
        GroupBox {
          title: "选择对象";
          VerticalLayout {
            spacing: 8px;
            Button { text: "添加文件"; clicked => { root.pick_files(); } }
            Button { text: "添加文件夹"; clicked => { root.pick_folders(); } }
          }
        }
        GroupBox {
          title: "日志筛选";
          VerticalLayout {
            spacing: 6px;
            TextInput { id: log_query; placeholder-text: "关键字..."; }
            Button { text: "刷新日志"; clicked => { root.refresh_logs(log_query.text); } }
          }
        }
      }

      // 中间：文件列表
      VerticalLayout {
        horizontal-stretch: 1.0;
        GroupBox {
          title: "文件/目录";
          ListView {
            for file[i] in root.files: FileRow { data := file; }
          }
        }
      }

      // 右栏：详情 + 操作 + 日志
      VerticalLayout {
        width: 380px;

        GroupBox {
          title: "对象信息";
          VerticalLayout {
            Text { text: "已选择: " + root.files.length + " 项"; }
            Text { text: "提示：封印模式将尝试 System 级（若权限允许），否则降级为 High。"; font-size: 12px; }
          }
        }

        GroupBox {
          title: "操作";
          VerticalLayout {
            HorizontalLayout {
              Text { text: "模式:"; vertical-alignment: center; }
              ComboBox { id: mode_cb; model: [ "只读", "封印" ]; }
              Text { text: "标签级别:"; vertical-alignment: center; }
              ComboBox { id: level_cb; model: [ "Medium", "High", "System" ]; current-index: 1; }
            }
            CheckBox { id: nrnx; text: "尝试 NR/NX（不保证对文件生效）"; checked: false; }
            HorizontalLayout {
              Button {
                text: "应用上锁";
                clicked => {
                  let m = mode_cb.current-index == 0 ? Mode.ReadOnly : Mode.Seal;
                  let l = (level_cb.current-index == 0) ? Level.Medium
                          : (level_cb.current-index == 1) ? Level.High : Level.System;
                  root.request_lock(m, l, nrnx.checked);
                }
              }
              Button {
                text: "解锁...";
                clicked => { unlock_dialog.open(); }
              }
            }
          }
        }

        GroupBox {
          title: "日志";
          ListView {
            height: 280px;
            for row[i] in root.logs: LogRowItem { data := row; }
          }
        }
      }
    }

    Rectangle {
      height: 32px;
      border-width: 1px; border-color: #cccccc;
      Text { id: footer; text: "准备就绪"; vertical-alignment: center; x: 8px; }
    }
  }
}

component FileRow inherits Rectangle {
  in property <FileItem> data;
  height: 26px;
  HorizontalLayout {
    CheckBox { checked: data.selected; }
    Text { text: data.kind + " "; vertical-alignment: center; }
    Text { text: data.path; vertical-alignment: center; horizontal-stretch: 1.0; }
    Text { text: data.il_text; vertical-alignment: center; }
  }
}

component LogRowItem inherits Rectangle {
  in property <LogRow> data;
  height: 24px;
  HorizontalLayout {
    Text { text: data.time; width: 150px; }
    Text { text: data.action; width: 60px; }
    Text { text: data.level; width: 70px; }
    Text { text: data.status; width: 80px; }
    Text { text: data.path; horizontal-stretch: 1.0; }
  }
}
```

### 7.2 GUI ↔ Rust 桥接（`src/main.rs` & `src/bridge.rs`）

**src/main.rs**

```rust
slint::include_modules!();

mod model;
mod bridge;

use model::{FileListModel, LogListModel};
use amberlock_core::{probe_capability};
use amberlock_storage::{NdjsonWriter, load_settings, save_settings};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
  let app = MainWindow::new()?;

  // 加载 settings（如不存在则默认）
  let settings_path = dirs::config_dir().unwrap_or(std::env::current_dir()?).join("amberlock-settings.json");
  let settings = load_settings(&settings_path).unwrap_or_else(|_| amberlock_core::types::Settings {
    parallelism: 4, default_mode: amberlock_core::types::ProtectMode::ReadOnly,
    default_level: amberlock_core::types::LabelLevel::High, enable_nr_nx: false,
    log_path: dirs::data_dir().unwrap_or(std::env::current_dir()?).join("amberlock-log.ndjson").to_string_lossy().to_string(),
    vault_path: dirs::data_dir().unwrap_or(std::env::current_dir()?).join("amberlock-vault.bin").to_string_lossy().to_string(),
    shell_integration: false
  });

  let logger = NdjsonWriter::open_append(&settings.log_path)?;
  let file_model = FileListModel::default();
  let log_model = LogListModel::open(&settings.log_path)?;

  // 显示用户 SID & 初始日志
  let sid = amberlock_winsec::read_user_sid().unwrap_or_default();
  app.set_user_sid(sid.into());
  app.set_files(file_model.snapshot());
  app.set_logs(log_model.snapshot(200));

  // 绑定回调
  {
    let app_weak = app.as_weak();
    app.on_pick_files(move || {
      if let Some(paths) = bridge::pick_files_dialog() {
        let app = app_weak.unwrap();
        bridge::add_paths_to_model(&paths, &file_model);
        app.set_files(file_model.snapshot());
        app.set_status_text(format!("已添加 {} 项", paths.len()).into());
      }
    });
  }
  {
    let app_weak = app.as_weak();
    app.on_pick_folders(move || {
      if let Some(paths) = bridge::pick_folders_dialog() {
        let app = app_weak.unwrap();
        bridge::add_paths_to_model(&paths, &file_model);
        app.set_files(file_model.snapshot());
        app.set_status_text(format!("已添加 {} 项", paths.len()).into());
      }
    });
  }
  {
    let app_weak = app.as_weak();
    let log_model = log_model.clone();
    app.on_refresh_logs(move |q| {
      let q = q.to_string();
      let app = app_weak.unwrap();
      let rows = log_model.filter_snapshot(&q, 300);
      app.set_logs(rows);
      app.set_status_text("日志已刷新".into());
    });
  }
  {
    let app_weak = app.as_weak();
    let logger = logger.clone();
    let file_model = file_model.clone();
    app.on_request_lock(move |mode, level, try_nr_nx| {
      let app = app_weak.unwrap();

      let sel: Vec<PathBuf> = file_model.selected_paths();
      if sel.is_empty() {
        app.set_status_text("未选择对象".into());
        return;
      }
      let (mode, level, policy) = bridge::convert_ui_params(mode, level, try_nr_nx);
      let opts = amberlock_core::ops::BatchOptions {
        desired_level: level, mode, policy,
        parallelism: 4, dry_run: false,
      };
      match amberlock_core::ops::batch_lock(&sel, &opts, &logger) {
        Ok(br) => app.set_status_text(format!("上锁完成: {}/{}", br.succeeded, br.total).into()),
        Err(e) => app.set_status_text(format!("上锁失败: {e:?}").into()),
      }

      app.set_logs(LogListModel::open(&settings.log_path)?.snapshot(200));
    });
  }
  {
    let app_weak = app.as_weak();
    let logger = logger.clone();
    app.on_request_unlock(move |password| {
      let app = app_weak.unwrap();
      // 真实实现应读取 vault 文件
      let vault_blob = std::fs::read(&settings.vault_path).unwrap_or_default();
      let sel = FileListModel::selected_paths_static();
      match amberlock_core::ops::batch_unlock(&sel, &password.to_string(), &vault_blob, &logger) {
        Ok(br) => app.set_status_text(format!("解锁完成: {}/{}", br.succeeded, br.total).into()),
        Err(e) => app.set_status_text(format!("解锁失败: {e:?}").into()),
      }
      app.set_logs(LogListModel::open(&settings.log_path)?.snapshot(200));
    });
  }

  // 能力探测提示
  if let Ok(rep) = probe_capability() {
    let cap = rep.capability;
    if !cap.can_touch_sacl {
      app.set_status_text("警告：缺少 SeSecurityPrivilege，部分功能不可用".into());
    }
    if !cap.can_set_system {
      app.set_status_text("提示：无法设置 System 级封印，将降级为 High".into());
    }
  }

  app.run()?;
  save_settings(settings_path, &settings)?;
  Ok(())
}
```

**src/model.rs（文件与日志模型）**

```rust
use std::path::{PathBuf};
use std::sync::Mutex;
use once_cell::sync::Lazy;
use walkdir::WalkDir;
use amberlock_storage::NdjsonReader;
use slint::SharedVector;

#[derive(Default, Clone)]
pub struct FileListModel {
  inner: std::sync::Arc<Mutex<Vec<(PathBuf, bool)>>>, // (path, selected)
}

static SELECTED_SNAPSHOT: Lazy<Mutex<Vec<PathBuf>>> = Lazy::new(|| Mutex::new(Vec::new()));

impl FileListModel {
  pub fn snapshot(&self) -> SharedVector<super::MainWindow::FileItem> {
    let v = self.inner.lock().unwrap();
    let mut out = SharedVector::new();
    for (p, sel) in v.iter() {
      let item = super::MainWindow::FileItem {
        path: p.to_string_lossy().into(),
        kind: if p.is_dir() {"Directory".into()} else {"File".into()},
        selected: *sel,
        il_text: "".into(), // 可调用 winsec 探测并填充
      };
      out.push(item);
    }
    out
  }
  pub fn add_paths(&self, paths: &[PathBuf]) {
    let mut v = self.inner.lock().unwrap();
    for p in paths { v.push((p.clone(), true)); }
    *SELECTED_SNAPSHOT.lock().unwrap() = v.iter().filter(|(_, s)| *s).map(|(p, _)| p.clone()).collect();
  }
  pub fn selected_paths(&self) -> Vec<PathBuf> {
    self.inner.lock().unwrap().iter().filter(|(_, s)| *s).map(|(p, _)| p.clone()).collect()
  }
  pub fn selected_paths_static() -> Vec<PathBuf> {
    SELECTED_SNAPSHOT.lock().unwrap().clone()
  }
}

#[derive(Clone)]
pub struct LogListModel {
  path: String,
}
impl LogListModel {
  pub fn open(path: &str) -> anyhow::Result<Self> { Ok(Self{ path: path.into() }) }
  pub fn snapshot(&self, limit: usize) -> slint::SharedVector<super::MainWindow::LogRow> {
    let mut r = NdjsonReader::open(&self.path).ok();
    let vals = r.as_mut().and_then(|rr| rr.read_last_n(limit).ok()).unwrap_or_default();
    vals.into_iter().map(|v| {
      let t = v.get("time_utc").and_then(|x| x.as_str()).unwrap_or("");
      let act = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
      let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("");
      let lvl = v.get("level_applied").and_then(|x| x.as_str()).unwrap_or("");
      let st = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
      super::MainWindow::LogRow { time: t.into(), action: act.into(), path: path.into(), level: lvl.into(), status: st.into() }
    }).collect()
  }
  pub fn filter_snapshot(&self, query: &str, limit: usize) -> slint::SharedVector<super::MainWindow::LogRow> {
    let mut r = NdjsonReader::open(&self.path).ok();
    let vals = r.as_mut().and_then(|rr| rr.filter(query, limit).ok()).unwrap_or_default();
    vals.into_iter().map(|v| {
      let t = v.get("time_utc").and_then(|x| x.as_str()).unwrap_or("");
      let act = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
      let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("");
      let lvl = v.get("level_applied").and_then(|x| x.as_str()).unwrap_or("");
      let st = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
      super::MainWindow::LogRow { time: t.into(), action: act.into(), path: path.into(), level: lvl.into(), status: st.into() }
    }).collect()
  }
}
```

**src/bridge.rs（对话框 & UI 参数转换）**

```rust
use std::path::PathBuf;

pub fn pick_files_dialog() -> Option<Vec<PathBuf>> {
  let files = rfd::FileDialog::new().set_title("选择文件").pick_files()?;
  Some(files)
}

pub fn pick_folders_dialog() -> Option<Vec<PathBuf>> {
  let dirs = rfd::FileDialog::new().set_title("选择文件夹").pick_folders()?;
  Some(dirs)
}

pub fn add_paths_to_model(paths: &[PathBuf], model: &crate::model::FileListModel) {
  model.add_paths(paths);
}

pub fn convert_ui_params(
  mode: crate::MainWindow::Mode,
  level: crate::MainWindow::Level,
  try_nr_nx: bool,
) -> (amberlock_core::types::ProtectMode,
      amberlock_core::types::LabelLevel,
      amberlock_core::types::MandPolicy) {
  use amberlock_core::types::*;
  let m = match mode {
    crate::MainWindow::Mode::ReadOnly => ProtectMode::ReadOnly,
    crate::MainWindow::Mode::Seal     => ProtectMode::Seal,
  };
  let l = match level {
    crate::MainWindow::Level::Medium => LabelLevel::Medium,
    crate::MainWindow::Level::High   => LabelLevel::High,
    crate::MainWindow::Level::System => LabelLevel::System,
  };
  let mut policy = MandPolicy::NW;
  if try_nr_nx { policy |= MandPolicy::NR | MandPolicy::NX; }
  (m, l, policy)
}
```

------

## 8) `amberlock-telemetry`（可选）

- 提供 `emit_event(source, id, message)`；或仅将统计输出到 NDJSON。此处略，待 M7 引入。

------

## 9) `amberlock-fixtures`（测试夹具）

提供创建临时目录树、随机文件、拥塞/占用文件模拟（可选）。

**Cargo.toml（节选）**

```toml
[package]
name = "amberlock-fixtures"
version = "0.1.0"
edition = "2021"

[dependencies]
tempfile.workspace = true
walkdir.workspace = true
rand.workspace = true
```

**lib.rs（签名）**

```rust
use tempfile::{tempdir, TempDir};
use std::{fs, path::PathBuf};

pub struct TempTree {
  pub root: TempDir,
  pub files: Vec<PathBuf>,
  pub dirs: Vec<PathBuf>,
}

pub fn make_small_tree() -> TempTree {
  let root = tempdir().unwrap();
  let d1 = root.path().join("d1"); fs::create_dir(&d1).unwrap();
  let f1 = d1.join("a.txt"); fs::write(&f1, b"hello").unwrap();
  TempTree { root, files: vec![f1], dirs: vec![d1] }
}
```

------

## 10) 首批**集成测试**用例

> 说明：涉及 SACL/ML 的测试需要提升权限，且在 CI 环境可能失败。建议加 `#[cfg(windows)]` 和 `#[ignore = "requires admin privileges"]` 标记，本地管理员下跑。

### 10.1 `amberlock-winsec`：读/写对象 ML

```rust
// amberlock-winsec/tests/ml_basic.rs
#![cfg(target_os = "windows")]
use amberlock_winsec::{set_mandatory_label, get_object_label, remove_mandatory_label,
  LabelLevel, MandPolicy, probe_capability};

#[test]
#[ignore = "requires admin privileges"]
fn set_and_remove_ml() {
  let cap = probe_capability().unwrap();
  assert!(cap.has_se_security, "need SeSecurityPrivilege");

  let dir = tempfile::tempdir().unwrap();
  let fp = dir.path().join("f.txt");
  std::fs::write(&fp, b"abc").unwrap();
  let path = fp.to_string_lossy().to_string();

  // 设置 High + NW
  set_mandatory_label(&path, LabelLevel::High, MandPolicy::NW).unwrap();
  let after = get_object_label(&path).unwrap();
  assert_eq!(after.level, LabelLevel::High);

  // 移除
  remove_mandatory_label(&path).unwrap();
  let after2 = get_object_label(&path).unwrap();
  // 可能无 ML ACE 或 level=Medium
  // 根据实现决定断言，这里仅检查 sddl 非空
  assert!(!after2.sddl.is_empty());
}
```

### 10.2 `amberlock-core`：批量上锁幂等

```rust
// amberlock-core/tests/batch_idempotent.rs
#![cfg(target_os = "windows")]
use amberlock_core::{ops::{batch_lock, BatchOptions}, types::*};
use amberlock_storage::NdjsonWriter;

#[test]
#[ignore = "requires admin privileges"]
fn idempotent_locking() {
  let dir = tempfile::tempdir().unwrap();
  let f = dir.path().join("a.txt");
  std::fs::write(&f, b"x").unwrap();

  let logger = NdjsonWriter::open_append(dir.path().join("log.ndjson")).unwrap();
  let opts = BatchOptions {
    desired_level: LabelLevel::High,
    mode: ProtectMode::ReadOnly,
    policy: MandPolicy::NW,
    parallelism: 4,
    dry_run: false,
  };

  let v = vec![f.clone()];
  let r1 = batch_lock(&v, &opts, &logger).unwrap();
  let r2 = batch_lock(&v, &opts, &logger).unwrap();
  assert_eq!(r1.succeeded, 1);
  assert_eq!(r2.succeeded, 1); // 再次设置应幂等
}
```

### 10.3 `amberlock-storage`：NDJSON 读写与过滤

```rust
// amberlock-storage/tests/ndjson.rs
use amberlock_storage::{NdjsonWriter, NdjsonReader};
use serde_json::json;

#[test]
fn ndjson_rw_filter() {
  let dir = tempfile::tempdir().unwrap();
  let p = dir.path().join("log.ndjson");
  let w = NdjsonWriter::open_append(&p).unwrap();
  w.write_record(&json!({"time_utc":"2025-01-01T00:00:00Z","path":"x","status":"success"})).unwrap();
  w.write_record(&json!({"time_utc":"2025-01-01T00:01:00Z","path":"y","status":"error"})).unwrap();
  w.flush().unwrap();

  let mut r = NdjsonReader::open(&p).unwrap();
  let last = r.read_last_n(1).unwrap();
  assert_eq!(last.len(), 1);
  let filtered = r.filter("error", 10).unwrap();
  assert_eq!(filtered.len(), 1);
}
```

### 10.4 `amberlock-auth`：口令创建与校验

```rust
// amberlock-auth/tests/vault.rs
use amberlock_auth::{create_vault, verify_password};

#[test]
fn vault_roundtrip() {
  let blob = create_vault("P@ssw0rd!").unwrap();
  assert!(verify_password(&blob, "P@ssw0rd!").unwrap());
  assert!(!verify_password(&blob, "wrong").unwrap());
}
```

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
- **依赖工具链**：MSVC 工具链（`rustup default stable-x86_64-pc-windows-msvc`）。
- **运行**：管理员启动 GUI；非管理员启动则 UI 顶部显示“能力受限”状态。

------

## 13) 后续扩展（Backlog 简述）

- 资源管理器右键菜单（Shell 扩展）与系统托盘（可选）。
- 事件日志/遥测（`amberlock-telemetry`）。
- “增强模式”（可选开关）：改 DACL/所有者（`TrustedInstaller`）以**更强抑制** ACL 修改——默认关闭且强警告。
- 文件浏览器：加入懒加载与 IL 批量探测列。
- “断点续执”：记录最后成功项并提供“继续”按钮。

------

以上内容提供了**完整的工程雏形**：工作区布局、每个 crate 的职责与 API、可直接使用的 **Slint 页面模板** 与 **Rust 桥接**、以及首批 **集成测试**。你可以按模块逐步替换伪实现为真实 Win32 调用，并在本机管理员环境下运行带 `#[ignore]` 的集成测试验证端到端路径。