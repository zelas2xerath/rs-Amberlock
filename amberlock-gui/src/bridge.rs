//! 文件对话框和参数转换工具函数
//!
//! 本模块提供了文件选择对话框的封装以及UI参数到内部类型的转换功能。

use crate::{Level, Mode};
use amberlock_types::{ProtectMode,LabelLevel};
use std::path::PathBuf;

/// 打开文件选择对话框，允许用户选择一个或多个文件
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
pub fn pick_folders_dialog() -> Option<Vec<PathBuf>> {
    let dirs = rfd::FileDialog::new()
        .set_title("选择文件夹")
        // 等待用户选择文件夹，如果取消则返回None
        .pick_folders()?;
    Some(dirs)
}

/// 将文件/文件夹路径添加到文件列表模型中
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
