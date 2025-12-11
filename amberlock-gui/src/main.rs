//! AmberLock 图形用户界面主应用程序模块
//!

use amberlock_core::{
    batch_process_lock, batch_process_unlock, LockOptions,
};
use amberlock_gui::{
    bridge,
    model::{FileListModel, LogListModel},
    MainWindow,
};
use amberlock_storage::{load_settings, save_settings, NdjsonWriter};
use amberlock_types::*;
use amberlock_winsec::{compute_effective_level, read_user_sid, token};
use slint::ComponentHandle;
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
///
fn main() -> anyhow::Result<()> {
    let app = MainWindow::new()?;

    // 加载设置
    let settings = load_application_settings()?;
    let (logger, file, log_model, user_sid, effective_level) =
        initialize_application_models(&settings)?;

    setup_initial_ui_state(&app, file.clone(), log_model.clone())?;

    // 绑定所有用户界面事件处理器
    setup_event_handlers(
        &app,
        settings.clone(),
        logger.clone(),
        file.clone(),
        log_model,
        user_sid,
        effective_level,
    )?;

    // 显示能力警告和欢迎信息
    show_startup_info(&app)?;

    app.run()?;

    // 退出时保存设置
    let settings_path = get_settings_path()?;
    save_settings(settings_path, &settings.read().unwrap())?;

    Ok(())
}

// === 初始化函数 ===

/// 加载应用程序设置
///
/// 尝试从用户配置目录加载现有设置文件，如果文件不存在或加载失败，
/// 则创建并使用默认设置。
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
fn create_default_settings() -> anyhow::Result<Arc<RwLock<Settings>>> {
    let log_path = get_default_data_path("amberlock-log.ndjson")?;
    let vault_path = get_default_data_path("amberlock-vault.bin")?;

    Ok(Arc::new(RwLock::new(Settings {
        parallelism: 4,
        default_mode: ProtectMode::ReadOnly,
        default_level: LabelLevel::High,
        log_path,
        vault_path,
        shell_integration: false,
    })))
}

/// 获取应用程序设置文件路径
///
/// 优先使用操作系统的标准配置目录，如果无法确定，则回退到当前工作目录。
/// - Windows: `%APPDATA%\amberlock-settings.json`
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
fn get_default_data_path(filename: &str) -> anyhow::Result<String> {
    Ok(dirs::data_dir()
        .unwrap_or(std::env::current_dir()?)
        .join(filename)
        .to_string_lossy()
        .to_string())
}

fn initialize_application_models(
    settings: &Arc<RwLock<Settings>>,
) -> anyhow::Result<(
    Arc<Mutex<NdjsonWriter>>,
    Arc<Mutex<FileListModel>>,
    Arc<Mutex<LogListModel>>,
    String,
    LabelLevel,
)> {
    // 以追加模式打开日志文件，如果文件不存在则创建
    let log_path = { settings.read().unwrap().log_path.clone() };

    let logger = Arc::new(Mutex::new(NdjsonWriter::open_append(&log_path)?));

    // 创建空的文件列表模型
    let file_model = Arc::new(Mutex::new(FileListModel::default()));

    // 从日志文件加载日志列表模型
    let log_model = Arc::new(Mutex::new(LogListModel::open(&log_path)?));

    let user_sid = read_user_sid()?;
    let cap = token::probe_capability()?;
    let effective_level = compute_effective_level(LabelLevel::System, cap.has_se_relabel);

    Ok((logger, file_model, log_model, user_sid, effective_level))
}

/// 设置用户界面初始状态
///
/// 在应用程序启动时，将数据模型的当前状态同步到用户界面，
/// 包括当前用户的 SID、文件列表和日志列表。
fn setup_initial_ui_state(
    app: &MainWindow,
    file_model: Arc<Mutex<FileListModel>>,
    log_model: Arc<Mutex<LogListModel>>,
) -> anyhow::Result<()> {
    // 获取当前用户的 Windows 安全标识符
    let sid = amberlock_winsec::read_user_sid().unwrap_or_else(|_| "未知".to_string());
    app.set_user_sid(sid.into());

    // 将文件列表模型快照绑定到 UI
    app.set_files(file_model.lock().unwrap().to_model_rc());

    // 将日志列表模型快照绑定到 UI（限制显示最近200条）
    app.set_logs(log_model.lock().unwrap().to_model_rc(200));

    Ok(())
}

// === 事件处理器设置 ===

fn setup_event_handlers(
    app: &MainWindow,
    settings: Arc<RwLock<Settings>>,
    logger: Arc<Mutex<NdjsonWriter>>,
    file_model: Arc<Mutex<FileListModel>>,
    log_model: Arc<Mutex<LogListModel>>,
    user_sid: String,
    effective_level: LabelLevel,
) -> anyhow::Result<()> {
    setup_file_selection_handlers(app, file_model.clone());
    setup_log_refresh_handler(app, log_model.clone());
    setup_lock_handler(
        app,
        settings.clone(),
        logger.clone(),
        file_model.clone(),
        effective_level,
        user_sid.clone(),
    );
    setup_unlock_handler(app, settings.clone(), logger.clone(), user_sid);
    Ok(())
}

/// 设置文件选择事件处理器
///
/// 处理用户通过 UI 选择文件和文件夹的操作，将选择结果添加到文件列表模型。
fn setup_file_selection_handlers(app: &MainWindow, file_model: Arc<Mutex<FileListModel>>) {
    // 处理选择文件事件
    {
        // 创建弱引用以避免循环引用
        let app_weak = app.as_weak();
        let file_model = Arc::clone(&file_model);
        app.on_pick_files(move || {
            // 打开系统文件选择对话框
            if let Some(paths) = bridge::pick_files_dialog() {
                let app = app_weak.unwrap();
                let mut fm = file_model.lock().unwrap();
                // 将选择的路径添加到文件模型
                bridge::add_paths_to_model(&paths, &mut *fm);
                let rc = fm.to_model_rc();
                drop(fm);
                // 更新 UI 中的文件列表
                app.set_files(rc);
                app.set_status_text(format!("✅ 已添加 {} 个文件", paths.len()).into());
            }
        });
    }

    // 处理选择文件夹事件
    {
        let app_weak = app.as_weak();
        let file_model = Arc::clone(&file_model);
        app.on_pick_folders(move || {
            // 打开系统文件夹选择对话框
            if let Some(paths) = bridge::pick_folders_dialog() {
                let app = app_weak.unwrap();

                let mut fm = file_model.lock().unwrap();
                // 将选择的路径添加到文件模型
                bridge::add_paths_to_model(&paths, &mut *fm);
                let rc = fm.to_model_rc();
                drop(fm);

                // 更新 UI 中的文件列表
                app.set_files(rc);
                app.set_status_text(format!("✅ 已添加 {} 个文件夹", paths.len()).into());
            }
        });
    }
}

/// 设置日志刷新事件处理器
///
/// 处理用户刷新日志列表的请求，支持按查询字符串过滤日志条目。
fn setup_log_refresh_handler(app: &MainWindow, log_model: Arc<Mutex<LogListModel>>) {
    let app_weak = app.as_weak();

    app.on_refresh_logs(move |query| {
        let query = query.to_string();
        let app = app_weak.unwrap();

        let rows = log_model
            .lock()
            .unwrap()
            .to_filtered_model_rc(&query, 300);

        // 更新 UI 中的日志列表
        app.set_logs(rows);

        if query.is_empty() {
            app.set_status_text("✅ 日志已刷新（显示全部）".into());
        } else {
            app.set_status_text(format!("🔍 日志已过滤: \"{}\"", query).into());
        }
    });
}

/// 设置锁定操作事件处理器
///
fn setup_lock_handler(
    app: &MainWindow,
    settings: Arc<RwLock<Settings>>,
    logger: Arc<Mutex<NdjsonWriter>>,
    file_model: Arc<Mutex<FileListModel>>,
    effective_level: LabelLevel,
    user_sid: String,
) {
    let app_weak = app.as_weak();

    app.on_request_lock(move |mode, level, _| {
        let app = app_weak.unwrap();

        // 获取选中的路径
        let selected_paths = file_model.lock().unwrap().selected_paths();

        // 检查是否有选中的项
        if selected_paths.is_empty() {
            app.set_status_text("⚠️ 未选择任何对象".into());
            return;
        }

        // 转换 UI 参数为核心库参数
        let (mode, level) = bridge::convert_ui_params(mode, level);

        let opts = LockOptions {
            desired_level: level,
            mode,
            parallelism: { settings.read().unwrap().parallelism },
        };

        // 批量操作
        let batch_result = batch_process_lock(
            &selected_paths,
            &opts,
            effective_level,
            &user_sid,
            &logger.lock().unwrap(),
        );

        // 显示详细的操作结果
        let status = format_batch_result(&batch_result);
        app.set_status_text(status.into());

        // 刷新日志
        refresh_logs_in_ui(&app, &settings);
    });
}

/// 设置解锁操作事件处理器
fn setup_unlock_handler(
    app: &MainWindow,
    settings: Arc<RwLock<Settings>>,
    logger: Arc<Mutex<NdjsonWriter>>,
    user_sid: String,
) {
    let app_weak = app.as_weak();

    app.on_request_unlock(move |_password| {
        let app = app_weak.unwrap();

        let selected_paths = FileListModel::selected_paths_static();

        if selected_paths.is_empty() {
            app.set_status_text("⚠️ 未选择任何对象".into());
            return;
        }

        // 批量操作
        let batch_result = batch_process_unlock(
            &selected_paths,
            &user_sid,
            &logger.lock().unwrap(),
        );

        // 显示批量操作结果
        let status = format_batch_result(&batch_result);
        app.set_status_text(status.into());

        // 刷新日志
        refresh_logs_in_ui(&app, &settings);
    });
}

// === 启动信息显示 ===

fn show_startup_info(app: &MainWindow) -> anyhow::Result<()> {
    match token::probe_capability() {
        Ok(report) => {
            let mut warnings = Vec::new();

            if !report.has_se_security {
                warnings.push("⚠️ 缺少 SeSecurityPrivilege，功能受限");
            }

            if !report.has_se_relabel {
                warnings.push("ℹ️ 无法设置 System 级，将自动降级为 High");
            }

            if warnings.is_empty() {
                app.set_status_text(
                    format!(
                        "✅ 就绪 - 完整性级别: {:?} | 版本: 2.0.0",
                        report.caller_il
                    )
                        .into(),
                );
            } else {
                app.set_status_text(warnings.join(" | ").into());
            }
        }
        Err(e) => {
            app.set_status_text(format!("⚠️ 能力探测失败: {:?}", e).into());
        }
    }

    Ok(())
}

// === 辅助函数 ===

/// 格式化批量操作结果（任务 7.1：清晰的错误提示）
fn format_batch_result(result: &amberlock_core::BatchResult) -> String {
    if result.failed_count == 0 {
        if result.downgraded_count > 0 {
            format!(
                "✅ 操作成功：完成 {} 个（其中 {} 个已降级）",
                result.success_count, result.downgraded_count
            )
        } else {
            format!("✅ 操作成功：完成 {} 个", result.success_count)
        }
    } else {
        format!(
            "⚠️ 操作部分失败：成功 {} 个，失败 {} 个{}",
            result.success_count,
            result.failed_count,
            if result.downgraded_count > 0 {
                format!("，降级 {} 个", result.downgraded_count)
            } else {
                String::new()
            }
        )
    }
}

/// 刷新日志显示
fn refresh_logs_in_ui(app: &MainWindow, settings: &Arc<RwLock<Settings>>) {
    let log_path = { settings.read().unwrap().log_path.clone() };
    if let Ok(log_model) = LogListModel::open(&log_path) {
        app.set_logs(log_model.to_model_rc(200));
    }
}