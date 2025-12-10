//! 文件对话框和参数转换工具函数
//!
//! 本模块提供了文件选择对话框的封装以及UI参数到内部类型的转换功能。

use crate::{Level, Mode};
use amberlock_types::{ProtectMode,LabelLevel};
use std::path::PathBuf;

/// 打开文件选择对话框，允许用户选择一个或多个文件
///
/// # 返回值
///
/// - `Some(Vec<PathBuf>)`: 用户选择的文件路径集合，按选择顺序排列
/// - `None`: 用户取消选择或对话框关闭
///
/// # 示例
///
/// ```rust
/// if let Some(files) = pick_files_dialog() {
///     for path in files {
///         println!("已选择文件: {:?}", path);
///     }
/// }
/// ```
///
/// # 注意
///
/// 该函数使用`rfd`库创建原生文件对话框，对话框标题为"选择文件"。
/// 返回的路径是绝对路径，用户可能没有读取权限，调用方需自行处理。
pub fn pick_files_dialog() -> Option<Vec<PathBuf>> {
    // 创建文件对话框实例并设置标题
    let files = rfd::FileDialog::new()
        .set_title("选择文件")
        // 等待用户选择文件，如果取消则返回None
        .pick_files()?;
    // 将用户选择的文件路径包装在Some中返回
    Some(files)
}

/// 打开文件夹选择对话框，允许用户选择一个或多个文件夹
///
/// # 返回值
///
/// - `Some(Vec<PathBuf>)`: 用户选择的文件夹路径集合
/// - `None`: 用户取消选择或对话框关闭
///
/// # 示例
///
/// ```rust
/// if let Some(folders) = pick_folders_dialog() {
///     for path in folders {
///         println!("已选择文件夹: {:?}", path);
///     }
/// }
/// ```
///
/// # 注意
///
/// 该函数使用`rfd`库创建原生文件夹对话框，对话框标题为"选择文件夹"。
/// 返回的路径是绝对路径，某些操作系统可能不支持多选文件夹功能。
pub fn pick_folders_dialog() -> Option<Vec<PathBuf>> {
    let dirs = rfd::FileDialog::new()
        .set_title("选择文件夹")
        // 等待用户选择文件夹，如果取消则返回None
        .pick_folders()?;
    Some(dirs)
}

/// 将文件/文件夹路径添加到文件列表模型中
///
/// # 参数
///
/// - `paths`: 要添加的文件系统路径切片
/// - `model`: 目标文件列表模型的引用
///
/// # 注意
///
/// 该函数会调用模型自身的`add_paths`方法，具体的添加逻辑和去重策略
/// 由`FileListModel`的实现决定。路径不会在此函数中进行验证。
///
/// # 示例
///
/// ```rust
/// let mut model = FileListModel::new();
/// let paths = vec![PathBuf::from("/some/file.txt")];
/// add_paths_to_model(&paths, &model);
/// ```
pub fn add_paths_to_model(paths: &[PathBuf], model: &crate::model::FileListModel) {
    // 委托给模型自身的添加方法
    model.add_paths(paths);
}

/// 将UI参数转换为Amberlock内部使用的类型
///
/// 将Slint UI中的枚举和布尔选项转换为Amberlock类型系统所需的
/// 保护模式、标签级别和强制策略的组合。
pub fn convert_ui_params(
    mode: Mode,
    level: Level,
) -> (ProtectMode, LabelLevel) {
    use amberlock_types::*;

    // 转换保护模式：将UI的Mode枚举映射到内部的ProtectMode
    let m = match mode {
        Mode::ReadOnly => ProtectMode::ReadOnly,
        Mode::Seal => ProtectMode::Seal,
    };

    // 转换安全级别：将UI的Level枚举映射到内部的LabelLevel
    let l = match level {
        Level::Medium => LabelLevel::Medium,
        Level::High => LabelLevel::High,
        Level::System => LabelLevel::System,
    };

    // 返回转换后的三元组
    (m, l)
}
