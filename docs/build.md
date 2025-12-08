# AmberLock GUI 构建与部署指南

## 📋 前置要求

### 系统要求

- **操作系统**: Windows 10/11 或 Windows Server 2019+
- **架构**: x86_64 (64-bit)
- **权限**: 管理员权限（运行时）

### 开发工具

1. **Rust 工具链** (最新 stable)
   ```bash
   # 安装 Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # 验证安装
   rustc --version
   cargo --version
   ```

2. **Windows SDK**
    - Visual Studio 2022 Build Tools
    - Windows 10/11 SDK
    - 下载：https://visualstudio.microsoft.com/downloads/

3. **依赖库**
   ```bash
   # 安装 Slint 编译依赖（可选，已包含在项目中）
   cargo install slint-lsp
   ```

---

## 🔨 构建步骤

### 1. 克隆项目

```bash
git clone https://github.com/your-repo/amberlock.git
cd amberlock
```

### 2. 检查依赖

```bash
# 验证工作区结构
cargo metadata --format-version 1 | jq '.workspace_members'

# 应显示：
# - amberlock-types
# - amberlock-winsec
# - amberlock-auth
# - amberlock-storage
# - amberlock-core
# - amberlock-gui
```

### 3. 开发构建

```bash
# 调试构建（快速，包含调试符号）
cargo build --bin amberlock-gui

# 运行（以管理员身份）
cargo run --bin amberlock-gui
```

**输出路径**: `target/debug/amberlock-gui.exe`

### 4. 发布构建

```bash
# 优化构建（体积小，速度快）
cargo build --release --bin amberlock-gui

# 进一步优化（启用 LTO）
cargo build --release --bin amberlock-gui --config profile.release.lto=true
```

**输出路径**: `target/release/amberlock-gui.exe`

---

## 🎛️ 构建配置

### Cargo.toml 优化

在 `amberlock-gui/Cargo.toml` 中添加：

```toml
[profile.release]
opt-level = 3          # 最高优化级别
lto = "fat"            # 完整链接时优化
codegen-units = 1      # 单编译单元（更好的优化）
strip = true           # 移除调试符号
panic = "abort"        # Panic 时直接中止（减小体积）
```

**构建配置说明**:

| 配置项 | 说明 | 影响 |
|--------|------|------|
| `opt-level = 3` | 最高优化 | +速度 / +构建时间 |
| `lto = "fat"` | 完整 LTO | +速度 -体积 / ++构建时间 |
| `codegen-units = 1` | 单编译单元 | +速度 / +构建时间 |
| `strip = true` | 移除符号表 | -体积 / 无法调试 |
| `panic = "abort"` | 不展开 Panic | -体积 |

### 平台特定配置

在项目根目录创建 `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-msvc]
rustflags = [
    "-C", "target-feature=+crt-static",  # 静态链接 CRT
    "-C", "link-arg=/SUBSYSTEM:WINDOWS", # 无控制台窗口
]

[build]
target = "x86_64-pc-windows-msvc"
```

---

## 📦 打包与分发

### 1. 创建独立可执行文件

```bash
# 发布构建
cargo build --release --bin amberlock-gui

# 复制可执行文件到分发目录
mkdir -p dist
copy target\release\amberlock-gui.exe dist\

# 验证依赖（应无外部 DLL）
dumpbin /dependents dist\amberlock-gui.exe
```

**预期输出（应仅包含系统 DLL）**:
```
Dump of file amberlock-gui.exe

File Type: EXECUTABLE IMAGE

  Image has the following dependencies:

    KERNEL32.dll
    ADVAPI32.dll
    USER32.dll
    GDI32.dll
```

### 2. 创建安装包（使用 WiX Toolset）

#### 安装 WiX Toolset

```bash
# 下载 WiX 3.11+
# https://wixtoolset.org/releases/

# 或使用 Chocolatey
choco install wixtoolset
```

#### 创建 WiX 配置文件

创建 `installer/amberlock.wxs`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" 
           Name="AmberLock" 
           Language="1033" 
           Version="2.0.0" 
           Manufacturer="YourCompany" 
           UpgradeCode="YOUR-GUID-HERE">
    
    <Package InstallerVersion="200" 
             Compressed="yes" 
             InstallScope="perMachine" 
             Platform="x64" />

    <MajorUpgrade DowngradeErrorMessage="A newer version is already installed." />
    
    <MediaTemplate EmbedCab="yes" />

    <Feature Id="ProductFeature" Title="AmberLock" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLFOLDER" Name="AmberLock" />
      </Directory>
      
      <Directory Id="ProgramMenuFolder">
        <Directory Id="ApplicationProgramsFolder" Name="AmberLock"/>
      </Directory>
    </Directory>

    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="MainExecutable" Guid="YOUR-GUID-HERE">
        <File Id="AmberLockEXE" 
              Source="../target/release/amberlock-gui.exe" 
              KeyPath="yes">
          <Shortcut Id="StartMenuShortcut"
                    Directory="ApplicationProgramsFolder"
                    Name="AmberLock"
                    Icon="AppIcon"
                    WorkingDirectory="INSTALLFOLDER"
                    Advertise="yes" />
        </File>
      </Component>
    </ComponentGroup>

    <Icon Id="AppIcon" SourceFile="icon.ico" />
  </Product>
</Wix>
```

#### 编译安装包

```bash
# 编译 WiX 源文件
candle.exe installer\amberlock.wxs -out installer\amberlock.wixobj

# 链接生成 MSI
light.exe installer\amberlock.wixobj -out dist\AmberLock-2.0.0-x64.msi
```

### 3. 创建便携版 ZIP

```bash
# 创建便携包
cd dist
7z a AmberLock-2.0.0-portable-x64.zip amberlock-gui.exe

# 或使用 PowerShell
Compress-Archive -Path amberlock-gui.exe -DestinationPath AmberLock-2.0.0-portable-x64.zip
```

---

## 🚀 部署流程

### 选项 1: MSI 安装包

**优点**:
- ✅ 标准 Windows 安装体验
- ✅ 自动创建开始菜单快捷方式
- ✅ 支持静默安装
- ✅ 支持卸载

**安装**:
```bash
# 图形界面安装
start AmberLock-2.0.0-x64.msi

# 静默安装
msiexec /i AmberLock-2.0.0-x64.msi /quiet /norestart
```

**卸载**:
```bash
msiexec /x AmberLock-2.0.0-x64.msi /quiet
```

### 选项 2: 便携版

**优点**:
- ✅ 无需安装
- ✅ 可在 U 盘运行
- ✅ 不修改系统注册表

**使用**:
1. 解压 ZIP 到任意目录
2. 右键 `amberlock-gui.exe` → 以管理员身份运行

---

## 🧪 测试清单

### 构建后测试

- [ ] **基本功能**
    - [ ] 程序正常启动
    - [ ] 首次运行创建配置文件
    - [ ] 首次运行创建保险库

- [ ] **文件选择**
    - [ ] 添加单个文件
    - [ ] 添加多个文件
    - [ ] 添加文件夹
    - [ ] 添加卷根（显示警告）

- [ ] **锁定操作**
    - [ ] 只读模式 + High 级别
    - [ ] 封印模式 + System 级别（自动降级测试）
    - [ ] 批量锁定（10+ 文件）
    - [ ] 卷根锁定二次确认

- [ ] **解锁操作**
    - [ ] 使用正确密码解锁
    - [ ] 使用错误密码（应失败）
    - [ ] 批量解锁

- [ ] **日志功能**
    - [ ] 查看日志列表
    - [ ] 过滤日志（关键字搜索）
    - [ ] 刷新日志

- [ ] **错误处理**
    - [ ] 文件不存在
    - [ ] 权限不足
    - [ ] 保险库损坏
    - [ ] 磁盘空间不足

### 兼容性测试

- [ ] Windows 10 (21H2+)
- [ ] Windows 11 (22H2+)
- [ ] Windows Server 2019
- [ ] Windows Server 2022

### 性能测试

- [ ] 锁定 1000+ 文件
- [ ] 递归锁定大目录（10000+ 文件）
- [ ] 内存使用 < 100 MB
- [ ] CPU 使用 < 50%（空闲时）

---

## 📊 构建优化建议

### 减小可执行文件体积

1. **启用完整 LTO**
   ```toml
   [profile.release]
   lto = "fat"
   codegen-units = 1
   ```

   效果：减少 10-20%

2. **移除未使用的依赖**
   ```bash
   cargo tree --duplicates
   cargo udeps
   ```

3. **使用 UPX 压缩**
   ```bash
   # 下载 UPX: https://upx.github.io/
   upx --best --lzma dist\amberlock-gui.exe
   ```

   效果：减少 40-60%（但启动稍慢）

### 加速构建时间

1. **使用 Sccache**
   ```bash
   cargo install sccache
   
   # 设置环境变量
   $env:RUSTC_WRAPPER = "sccache"
   
   # 构建
   cargo build --release
   ```

2. **增加并行度**
   ```toml
   # .cargo/config.toml
   [build]
   jobs = 8  # 根据 CPU 核心数调整
   ```

3. **使用增量编译**（仅开发构建）
   ```toml
   [profile.dev]
   incremental = true
   ```

---

## 🔒 代码签名

### 获取代码签名证书

1. **企业证书** - 从 CA 购买
2. **自签名证书** - 开发测试用

```bash
# 创建自签名证书（测试用）
makecert -r -pe -n "CN=Your Company" -b 01/01/2025 -e 01/01/2026 -sky signature -sv test.pvk test.cer
pvk2pfx -pvk test.pvk -spc test.cer -pfx test.pfx
```

### 对可执行文件签名

```bash
# 使用 signtool（包含在 Windows SDK 中）
signtool sign /f test.pfx /p password /t http://timestamp.digicert.com dist\amberlock-gui.exe

# 验证签名
signtool verify /pa dist\amberlock-gui.exe
```

---

## 📚 CI/CD 集成

### GitHub Actions 示例

创建 `.github/workflows/build.yml`:

```yaml
name: Build and Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-windows:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        target: x86_64-pc-windows-msvc
        override: true
    
    - name: Cache cargo registry
      uses: actions/cache@v3
      with:
        path: ~/.cargo/registry
        key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Build release
      run: cargo build --release --bin amberlock-gui
    
    - name: Create ZIP
      run: |
        cd target/release
        7z a ../../AmberLock-${{ github.ref_name }}-x64.zip amberlock-gui.exe
    
    - name: Upload artifact
      uses: actions/upload-artifact@v3
      with:
        name: amberlock-windows
        path: AmberLock-*.zip
    
    - name: Create Release
      uses: softprops/action-gh-release@v1
      with:
        files: AmberLock-*.zip
        draft: false
        prerelease: false
```

---

## 🐛 常见构建问题

### 问题 1: 链接错误

**症状**:
```
error: linking with `link.exe` failed
```

**解决方案**:
- 安装 Visual Studio Build Tools
- 确保 Windows SDK 已安装
- 运行 `rustup default stable-x86_64-pc-windows-msvc`

### 问题 2: Slint 编译错误

**症状**:
```
error: failed to compile `main.slint`
```

**解决方案**:
- 检查 `ui/main.slint` 语法
- 更新 Slint 版本：`cargo update -p slint`

### 问题 3: 依赖冲突

**症状**:
```
error: failed to select a version for `serde`
```

**解决方案**:
```bash
cargo clean
cargo update
cargo build --release
```

---

## 📖 参考资源

- [Rust 编译器文档](https://doc.rust-lang.org/rustc/)
- [Cargo 构建配置](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [Windows 代码签名](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools)
- [WiX Toolset 教程](https://wixtoolset.org/documentation/manual/v3/)

---

**维护者**: Zelas2Xerath  
**最后更新**: 2025-01-01