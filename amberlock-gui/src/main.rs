//! AmberLock 图形用户界面主应用程序模块。
//!
//! 本模块提供基于 Slint GUI 框架的 AmberLock 主应用程序，包含以下功能：
//! - 文件和文件夹选择与批量管理
//! - 文件锁定与解锁操作
//! - 操作日志记录与查看
//! - 应用程序设置管理
//!
//! # 主要组件
//! - `bridge` 模块：处理与操作系统的交互（文件选择对话框等）
//! - `model` 模块：管理应用程序数据模型（文件列表、日志列表）
//! - 核心业务逻辑：调用 `amberlock_core` 和 `amberlock_storage` 执行实际操作
//!
//! # 启动流程
//! 1. 加载或创建应用程序设置
//! 2. 初始化数据模型（文件列表、日志记录器）
//! 3. 设置用户界面初始状态
//! 4. 绑定事件处理器
//! 5. 显示系统能力警告（如果需要）
//! 6. 运行GUI主循环
//! 7. 退出时保存设置

slint::include_modules!();

/// 系统桥接模块
///
/// 处理与操作系统相关的交互，如文件选择对话框、路径处理等。
mod bridge;

/// 数据模型模块
///
/// 包含管理应用程序数据的模型结构，如文件列表模型和日志列表模型。
mod model;
mod utils;

use amberlock_core::probe_capability;
use amberlock_storage::{load_settings, save_settings, NdjsonWriter};
use amberlock_types::*;
use model::{FileListModel, LogListModel};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

/// AmberLock GUI 应用程序的主入口点
///
/// # 执行流程
/// 1. 加载或创建应用程序设置
/// 2. 初始化数据模型和日志记录器
/// 3. 设置用户界面初始状态
/// 4. 绑定所有用户界面事件处理器
/// 5. 检查并显示系统能力警告
/// 6. 运行 GUI 主事件循环
/// 7. 退出时保存当前设置
///
/// # 返回值
/// - `Ok(())`：应用程序正常退出
/// - `Err(e)`：启动或运行过程中发生错误
///
/// # 错误处理
/// 使用 `anyhow::Result` 统一处理可能出现的各种错误，包括：
/// - 文件系统错误（读写设置、日志文件）
/// - GUI 初始化错误
/// - 模型初始化错误
///
/// # 示例
/// ```no_run
/// fn main() -> anyhow::Result<()> {
///     amberlock_ui::main()
/// }
/// ```
fn main() -> anyhow::Result<()> {
    // 创建并初始化主窗口
    let app = MainWindow::new()?;

    // 加载应用程序设置，如果不存在则创建默认设置
    let settings = load_application_settings()?;

    // 初始化应用程序核心数据模型
    let (logger, file_model, log_model) = initialize_application_models(&settings)?;

    // 设置用户界面的初始状态
    setup_initial_ui_state(&app, file_model.clone(), log_model.clone())?;

    // 绑定所有用户界面事件处理器
    setup_event_handlers(&app, settings.clone(), logger, file_model, log_model)?;

    // 检查并显示系统能力警告（如缺少必要权限）
    show_capability_warnings(&app)?;

    // 运行 GUI 主事件循环
    app.run()?;

    // 应用程序退出前保存当前设置
    let settings_path = get_settings_path()?;
    save_settings(settings_path, &settings.write().unwrap())?; //write here

    Ok(())
}

// === 辅助函数 ===

/// 加载应用程序设置
///
/// 尝试从用户配置目录加载现有设置文件，如果文件不存在或加载失败，
/// 则创建并使用默认设置。
///
/// # 返回
/// - `Ok(Settings)`：成功加载或创建的设置
/// - `Err(e)`：路径解析或文件读写错误
///
/// # 文件位置
/// 设置文件默认存储在：`${CONFIG_DIR}/amberlock-settings.json`
/// 其中 CONFIG_DIR 是操作系统的标准配置目录。
fn load_application_settings() -> anyhow::Result<Arc<RwLock<Settings>>> {
    let settings_path = get_settings_path()?;

    // 尝试加载现有设置，失败时创建默认设置
    match load_settings(&settings_path) {
        Ok(settings) => Ok(Arc::new(RwLock::new(settings))),
        Err(_) => create_default_settings(),
    }
}

/// 创建默认应用程序设置
///
/// 创建包含以下默认值的设置对象：
/// - 并行度：4
/// - 默认保护模式：只读
/// - 默认标签级别：高
/// - NR/NX 策略：禁用
/// - 日志文件路径：用户数据目录下的 `amberlock-log.ndjson`
/// - 保险库文件路径：用户数据目录下的 `amberlock-vault.bin`
/// - Shell 集成：禁用
///
/// # 返回
/// - `Ok(Settings)`：包含默认值的设置对象
/// - `Err(e)`：无法确定用户数据目录时返回错误
fn create_default_settings() -> anyhow::Result<Arc<RwLock<Settings>>> {
    let log_path = get_default_data_path("amberlock-log.ndjson")?;
    let vault_path = get_default_data_path("amberlock-vault.bin")?;

    Ok(Arc::new(RwLock::new(Settings {
        parallelism: 4, //let parallelism = { settings.lock().unwrap().parallelism };
        default_mode: ProtectMode::ReadOnly,
        default_level: LabelLevel::High,
        enable_nr_nx: false,
        log_path,
        vault_path,
        shell_integration: false,
    })))
}

/// 获取应用程序设置文件路径
///
/// 优先使用操作系统的标准配置目录，如果无法确定，则回退到当前工作目录。
///
/// # 返回
/// - `Ok(PathBuf)`：设置文件的完整路径
/// - `Err(e)`：无法获取当前工作目录时返回错误
///
/// # 平台特定行为
/// - Windows: `%APPDATA%\amberlock-settings.json`
/// - macOS: `~/Library/Application Support/amberlock-settings.json`
/// - Linux/Unix: `~/.config/amberlock-settings.json`
fn get_settings_path() -> anyhow::Result<PathBuf> {
    Ok(dirs::config_dir()
        .unwrap_or(std::env::current_dir()?)
        .join("amberlock-settings.json"))
}

/// 获取默认数据文件路径
///
/// 为指定文件名在用户数据目录中构建完整路径。
///
/// # 参数
/// - `filename`: 数据文件名（如 "amberlock-log.ndjson"）
///
/// # 返回
/// - `Ok(String)`：数据文件的完整路径字符串
/// - `Err(e)`：无法确定用户数据目录或当前工作目录时返回错误
///
/// # 平台特定行为
/// - Windows: `%APPDATA%\Local\<filename>`
/// - macOS: `~/Library/Application Support/<filename>`
/// - Linux/Unix: `~/.local/share/<filename>`
fn get_default_data_path(filename: &str) -> anyhow::Result<String> {
    Ok(dirs::data_dir()
        .unwrap_or(std::env::current_dir()?)
        .join(filename)
        .to_string_lossy()
        .to_string())
}

/// 初始化应用程序核心数据模型
///
/// 创建应用程序运行所需的三个核心组件：
/// 1. 日志记录器：用于记录所有操作日志
/// 2. 文件列表模型：管理用户选择的文件和文件夹
/// 3. 日志列表模型：管理日志显示和过滤
///
/// # 参数
/// - `settings`: 应用程序设置，包含日志文件路径等信息
///
/// # 返回
/// - `Ok((NdjsonWriter, FileListModel, LogListModel))`：成功初始化的三个模型
/// - `Err(e)`：文件打开或模型初始化失败时返回错误
fn initialize_application_models(
    settings: &Arc<RwLock<Settings>>,
) -> anyhow::Result<(Arc<Mutex<NdjsonWriter>>, Arc<Mutex<FileListModel>>, Arc<Mutex<LogListModel>>)> {
    // 以追加模式打开日志文件，如果文件不存在则创建
    let log_path = { settings.write().unwrap().log_path.clone() };
    let logger = Arc::new(Mutex::new(NdjsonWriter::open_append(&log_path)?));

    // 创建空的文件列表模型
    let file_model = Arc::new(Mutex::new(FileListModel::default()));

    // 从日志文件加载日志列表模型
    let log_model = Arc::new(Mutex::new(LogListModel::open(&log_path)?));

    Ok((logger, file_model, log_model))
}

/// 设置用户界面初始状态
///
/// 在应用程序启动时，将数据模型的当前状态同步到用户界面，
/// 包括当前用户的 SID、文件列表和日志列表。
///
/// # 参数
/// - `app`: Slint 主窗口引用
/// - `file_model`: 文件列表模型引用
/// - `log_model`: 日志列表模型引用
///
/// # 返回
/// - `Ok(())`：设置成功
/// - `Err(e)`：获取用户 SID 失败时返回错误
fn setup_initial_ui_state(
    app: &MainWindow,
    file_model: Arc<Mutex<FileListModel>>,
    log_model: Arc<Mutex<LogListModel>>,
) -> anyhow::Result<()> {
    // 获取当前用户的 Windows 安全标识符
    let sid = amberlock_winsec::read_user_sid().unwrap_or_default();
    app.set_user_sid(sid.into());

    // 将文件列表模型快照绑定到 UI
    app.set_files(file_model.lock().unwrap().to_model_rc());

    // 将日志列表模型快照绑定到 UI（限制显示最近200条）
    app.set_logs(log_model.lock().unwrap().to_model_rc(200));

    Ok(())
}

/// 设置所有用户界面事件处理器
///
/// 将用户界面事件（按钮点击、选择变更等）绑定到相应的处理函数。
///
/// # 参数
/// - `app`: Slint 主窗口引用
/// - `settings`: 应用程序设置引用
/// - `logger`: 日志记录器引用
/// - `file_model`: 文件列表模型引用
/// - `log_model`: 日志列表模型引用
///
/// # 返回
/// - `Ok(())`：所有处理器设置成功
///
/// # 绑定的事件类型
/// - 文件选择对话框
/// - 文件夹选择对话框
/// - 日志刷新
/// - 锁定操作
/// - 解锁操作
fn setup_event_handlers(
    app: &MainWindow,
    settings: Arc<RwLock<Settings>>,
    logger: Arc<Mutex<NdjsonWriter>>,
    file_model: Arc<Mutex<FileListModel>>,
    log_model: Arc<Mutex<LogListModel>>,
) -> anyhow::Result<()> {
    setup_file_selection_handlers(app, file_model.clone());
    setup_log_refresh_handler(app, log_model.clone()); //
    setup_lock_handler(app, settings.clone(), logger.clone(), file_model);
    setup_unlock_handler(app, settings, logger);

    Ok(())
}

/// 设置文件选择事件处理器
///
/// 处理用户通过 UI 选择文件和文件夹的操作，将选择结果添加到文件列表模型。
///
/// # 参数
/// - `app`: Slint 主窗口引用
/// - `file_model`: 文件列表模型引用
///
/// # 处理的操作
/// 1. 选择文件：打开系统文件选择对话框，添加选中的文件
/// 2. 选择文件夹：打开系统文件夹选择对话框，添加选中的文件夹
fn setup_file_selection_handlers(app: &MainWindow, file_model: Arc<Mutex<FileListModel>>) {
    // 处理选择文件事件
    {
        // 创建弱引用以避免循环引用
        let app_weak = app.as_weak();
        let file_model = Arc::clone(&file_model); // ⭐ 给这个闭包一份
        app.on_pick_files(move || {
            // 打开系统文件选择对话框
            if let Some(paths) = bridge::pick_files_dialog() {
                let app = app_weak.unwrap();
                let mut fm = file_model.lock().unwrap();
                // 将选择的路径添加到文件模型
                bridge::add_paths_to_model(&paths, &mut * fm);
                let rc = fm.to_model_rc();
                drop(fm);
                // 更新 UI 中的文件列表
                app.set_files(rc);

                // 显示状态消息
                app.set_status_text(format!("已添加 {} 项", paths.len()).into());
            }
        });
    }

    // 处理选择文件夹事件
    {
        let app_weak = app.as_weak();
        let file_model = Arc::clone(&file_model); // ⭐ 再给第二个闭包一份
        app.on_pick_folders(move || {
            // 打开系统文件夹选择对话框
            if let Some(paths) = bridge::pick_folders_dialog() {
                let app = app_weak.unwrap();
                let mut fm = file_model.lock().unwrap();
                // 将选择的路径添加到文件模型
                bridge::add_paths_to_model(&paths, &mut * fm);
                let rc = fm.to_model_rc();
                drop(fm);

                // 更新 UI 中的文件列表
                app.set_files(rc);

                // 显示状态消息
                app.set_status_text(format!("已添加 {} 项", paths.len()).into());
            }
        });
    }
}

/// 设置日志刷新事件处理器
///
/// 处理用户刷新日志列表的请求，支持按查询字符串过滤日志条目。
///
/// # 参数
/// - `app`: Slint 主窗口引用
/// - `log_model`: 日志列表模型引用
///
/// # 功能
/// - 根据查询字符串过滤日志条目
/// - 限制显示最多300条结果
/// - 更新 UI 中的日志列表
fn setup_log_refresh_handler(app: &MainWindow, log_model: Arc<Mutex<LogListModel>>) {
    let app_weak = app.as_weak();
    let log_model = log_model.clone();

    app.on_refresh_logs(move |query| {
        let query = query.to_string();
        let app = app_weak.unwrap();

        // 根据查询字符串过滤日志并获取快照
        let rows = log_model.lock().unwrap().to_filtered_model_rc(&query, 300);

        // 更新 UI 中的日志列表
        app.set_logs(rows);

        // 显示状态消息
        app.set_status_text("日志已刷新".into());
    });
}

/// 设置锁定操作事件处理器
///
/// 处理用户执行文件锁定操作的请求，调用核心库执行实际锁定操作，
/// 并记录操作结果到日志。
///
/// # 参数
/// - `app`: Slint 主窗口引用
/// - `settings`: 应用程序设置引用
/// - `logger`: 日志记录器引用
/// - `file_model`: 文件列表模型引用
///
/// # 操作流程
/// 1. 检查是否有选中的文件/文件夹
/// 2. 转换 UI 参数为核心库参数
/// 3. 调用 `batch_lock` 执行批量锁定
/// 4. 记录操作结果并更新状态
/// 5. 刷新日志列表显示
fn setup_lock_handler(
    app: &MainWindow,
    settings: Arc<RwLock<Settings>>,
    logger: Arc<Mutex<NdjsonWriter>>,
    file_model: Arc<Mutex<FileListModel>>,
) {
    let app_weak = app.as_weak();
    let logger = logger.clone();
    let file_model = file_model.clone();

    app.on_request_lock(move |mode, level, try_nr_nx| {
        let app = app_weak.unwrap();

        // 获取当前选中的路径
        let selected_paths: Vec<PathBuf> = file_model.lock().unwrap().selected_paths();

        // 检查是否有选中的项
        if selected_paths.is_empty() {
            app.set_status_text("未选择对象".into());
            return;
        }

        // 转换 UI 参数为核心库参数
        let (mode, level, policy) = bridge::convert_ui_params(mode, level, try_nr_nx);

        // 构建批量操作选项
        let opts = amberlock_core::ops::BatchOptions {
            desired_level: level,
            mode,
            policy,
            parallelism: 4,
            dry_run: false,
        };

        // 执行批量锁定操作
        match amberlock_core::ops::batch_lock(&selected_paths, &opts, &logger.lock().unwrap()) {
            Ok(batch_result) => {
                // 显示成功消息
                app.set_status_text(
                    format!(
                        "上锁完成: {}/{}",
                        batch_result.succeeded, batch_result.total
                    )
                    .into(),
                )
            }
            Err(error) => {
                // 显示错误消息
                app.set_status_text(format!("上锁失败: {error:?}").into())
            }
        }

        // 重新加载日志以显示最新操作记录
        let log_path = { settings.read().unwrap().log_path.clone() };
        if let Ok(log_model) = LogListModel::open(&log_path) {
            app.set_logs(log_model.to_model_rc(200));
        }
    });
}

/// 设置解锁操作事件处理器
///
/// 处理用户执行文件解锁操作的请求，验证密码并调用核心库执行解锁操作。
///
/// # 参数
/// - `app`: Slint 主窗口引用
/// - `settings`: 应用程序设置引用（包含保险库文件路径）
/// - `logger`: 日志记录器引用
///
/// # 安全注意
/// - 密码在内存中的处理时间应尽可能短
/// - 保险库文件应加密存储
/// - 解锁失败不应泄露具体原因（避免信息泄漏）
fn setup_unlock_handler(app: &MainWindow, settings: Arc<RwLock<Settings>>, logger: Arc<Mutex<NdjsonWriter>>) {
    let app_weak = app.as_weak();
    let logger = logger.clone();

    app.on_request_unlock(move |password| {
        let app = app_weak.unwrap();

        // 从保险库文件读取加密数据
        // 注意：真实实现中应处理文件不存在的情况
        let vault_blob = std::fs::read(&settings.read().unwrap().vault_path).unwrap_or_default();

        // 获取当前选中的路径（静态方法，从全局状态获取）
        let selected_paths = FileListModel::selected_paths_static();

        // 执行批量解锁操作
        match amberlock_core::ops::batch_unlock(
            &selected_paths,
            &password.to_string(),
            &vault_blob,
            &logger.lock().unwrap(),
        ) {
            Ok(batch_result) => {
                // 显示成功消息
                app.set_status_text(
                    format!(
                        "解锁完成: {}/{}",
                        batch_result.succeeded, batch_result.total
                    )
                    .into(),
                )
            }
            Err(error) => {
                // 显示错误消息（避免泄露具体错误细节）
                app.set_status_text(format!("解锁失败: {error:?}").into())
            }
        }

        // 重新加载日志以显示最新操作记录
        let log_path = { settings.read().unwrap().log_path.clone() };
        if let Ok(log_model) = LogListModel::open(&log_path) {
            app.set_logs(log_model.to_model_rc(200));
        }
    });
}

/// 显示系统能力警告
///
/// 检查当前系统是否支持 AmberLock 的所有功能，如果不支持，
/// 则在状态栏显示相应的警告信息。
///
/// # 参数
/// - `app`: Slint 主窗口引用
///
/// # 返回
/// - `Ok(())`：检查完成，无论是否有警告
///
/// # 检查的能力
/// - `can_touch_sacl`: 是否具有修改系统访问控制列表的权限（SeSecurityPrivilege）
/// - `can_set_system`: 是否能够设置 System 级别的文件标签
///
/// # 系统要求
/// - Windows 系统需要管理员权限或相应特权
/// - 某些功能可能需要额外的组策略设置
fn show_capability_warnings(app: &MainWindow) -> anyhow::Result<()> {
    // 探测系统能力
    if let Ok(capability_report) = probe_capability() {
        let capability = capability_report.capability;

        // 检查 SACL 修改权限
        if !capability.can_touch_sacl {
            app.set_status_text("警告：缺少 SeSecurityPrivilege，部分功能不可用".into());
        }

        // 检查 System 级别设置能力
        if !capability.can_set_system {
            app.set_status_text("提示：无法设置 System 级封印，将降级为 High".into());
        }
    }

    Ok(())
}
