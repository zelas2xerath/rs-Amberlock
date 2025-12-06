//! GUI 实用工具模块
//!
//! 提供GUI层的通用辅助功能，包括：
//! - 路径验证和规范化
//! - 用户友好的错误消息格式化
//! - 文件大小格式化
//! - 时间戳格式化

use std::path::{Path, PathBuf};

/// 验证路径是否存在且可访问
///
/// # 参数
/// - `path`: 要验证的路径
///
/// # 返回
/// - `Ok(PathBuf)`: 规范化后的绝对路径
/// - `Err(String)`: 验证失败的原因
pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
    // 检查路径是否存在
    if !path.exists() {
        return Err(format!("路径不存在: {}", path.display()));
    }

    // 尝试规范化路径（转换为绝对路径并解析符号链接）
    match path.canonicalize() {
        Ok(canonical_path) => Ok(canonical_path),
        Err(e) => Err(format!(
            "无法访问路径 {}: {}",
            path.display(),
            format_io_error(&e)
        )),
    }
}

/// 批量验证路径列表
///
/// # 参数
/// - `paths`: 要验证的路径切片
///
/// # 返回
/// - `Ok(Vec<PathBuf>)`: 所有验证通过的规范化路径
/// - `Err(String)`: 第一个验证失败的路径及原因
pub fn validate_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    paths.iter().map(|p| validate_path(p)).collect()
}

/// 格式化文件大小为人类可读字符串
///
/// # 参数
/// - `bytes`: 文件大小（字节）
///
/// # 返回
/// 格式化后的字符串（如 "1.5 MB"）
///
/// # 示例
/// ```
/// assert_eq!(format_file_size(1024), "1.0 KB");
/// assert_eq!(format_file_size(1536), "1.5 KB");
/// assert_eq!(format_file_size(1048576), "1.0 MB");
/// ```
pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// 格式化IO错误为用户友好的消息
///
/// # 参数
/// - `error`: std::io::Error 引用
///
/// # 返回
/// 简化的错误描述
pub fn format_io_error(error: &std::io::Error) -> String {
    use std::io::ErrorKind;

    match error.kind() {
        ErrorKind::NotFound => "文件或目录不存在".to_string(),
        ErrorKind::PermissionDenied => "权限被拒绝（可能需要管理员权限）".to_string(),
        ErrorKind::AlreadyExists => "文件或目录已存在".to_string(),
        ErrorKind::InvalidInput => "无效的输入参数".to_string(),
        ErrorKind::InvalidData => "数据格式无效或已损坏".to_string(),
        ErrorKind::TimedOut => "操作超时".to_string(),
        ErrorKind::WriteZero => "磁盘空间不足或文件系统只读".to_string(),
        ErrorKind::Interrupted => "操作被中断".to_string(),
        ErrorKind::UnexpectedEof => "文件意外结束".to_string(),
        _ => error.to_string(),
    }
}

/// 格式化 ISO8601 时间戳为本地可读格式
///
/// # 参数
/// - `iso_timestamp`: ISO8601 格式时间戳（如 "2025-01-01T12:00:00Z"）
///
/// # 返回
/// 本地化的可读时间字符串
///
/// # 示例
/// ```
/// let formatted = format_timestamp("2025-01-01T12:00:00Z");
/// // 可能输出: "2025-01-01 12:00:00"
/// ```
pub fn format_timestamp(iso_timestamp: &str) -> String {
    // 简化实现：直接替换 'T' 和 'Z'
    iso_timestamp
        .replace('T', " ")
        .replace('Z', "")
        .split('.')
        .next()
        .unwrap_or(iso_timestamp)
        .to_string()
}

/// 从完整路径提取文件名
///
/// # 参数
/// - `path`: 文件路径
///
/// # 返回
/// 文件名字符串，如果提取失败则返回完整路径
pub fn extract_filename(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_else(|| path.to_str().unwrap_or("未知文件"))
        .to_string()
}

/// 检查路径是否为卷根（如 C:\）
///
/// # 参数
/// - `path`: 要检查的路径
///
/// # 返回
/// 如果是卷根则返回 `true`
///
/// # 注意
/// 仅在 Windows 上有效，其他平台检查是否为 "/"
pub fn is_volume_root(path: &Path) -> bool {
    #[cfg(windows)]
    {
        // Windows: 检查路径是否为 X:\ 形式
        let path_str = path.to_string_lossy();
        if path_str.len() == 3 {
            let bytes = path_str.as_bytes();
            bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
        } else {
            false
        }
    }

    #[cfg(not(windows))]
    {
        path == Path::new("/")
    }
}

/// 安全地截断路径字符串以适应UI显示
///
/// # 参数
/// - `path`: 原始路径字符串
/// - `max_len`: 最大长度（字符数）
///
/// # 返回
/// 截断后的路径，中间部分用 "..." 替代
///
/// # 示例
/// ```
/// let long_path = "C:\\Users\\Username\\Documents\\Projects\\LongProjectName\\file.txt";
/// let truncated = truncate_path_for_display(long_path, 40);
/// // 可能输出: "C:\\Users\\...\\LongProjectName\\file.txt"
/// ```
pub fn truncate_path_for_display(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_string();
    }

    // 计算前后各保留多少字符
    let keep_front = (max_len - 3) / 2;
    let keep_back = max_len - 3 - keep_front;

    format!(
        "{}...{}",
        &path[..keep_front],
        &path[path.len() - keep_back..]
    )
}

/// 格式化操作持续时间
///
/// # 参数
/// - `duration_ms`: 持续时间（毫秒）
///
/// # 返回
/// 格式化的时间字符串
///
/// # 示例
/// ```
/// assert_eq!(format_duration(500), "500 ms");
/// assert_eq!(format_duration(1500), "1.5 s");
/// assert_eq!(format_duration(65000), "1m 5s");
/// ```
pub fn format_duration(duration_ms: u64) -> String {
    if duration_ms < 1000 {
        format!("{} ms", duration_ms)
    } else if duration_ms < 60000 {
        format!("{:.1} s", duration_ms as f64 / 1000.0)
    } else {
        let minutes = duration_ms / 60000;
        let seconds = (duration_ms % 60000) / 1000;
        format!("{}m {}s", minutes, seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(1023), "1023 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
        assert_eq!(format_file_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_format_timestamp() {
        assert_eq!(
            format_timestamp("2025-01-01T12:00:00Z"),
            "2025-01-01 12:00:00"
        );
        assert_eq!(
            format_timestamp("2025-12-31T23:59:59.999Z"),
            "2025-12-31 23:59:59"
        );
    }

    #[test]
    fn test_truncate_path_for_display() {
        let short_path = "C:\\test\\file.txt";
        assert_eq!(truncate_path_for_display(short_path, 50), short_path);

        let long_path = "C:\\Users\\LongUsername\\Documents\\Projects\\VeryLongProjectName\\file.txt";
        let truncated = truncate_path_for_display(long_path, 40);
        assert_eq!(truncated.len(), 40);
        assert!(truncated.contains("..."));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500), "500 ms");
        assert_eq!(format_duration(1500), "1.5 s");
        assert_eq!(format_duration(65000), "1m 5s");
        assert_eq!(format_duration(125000), "2m 5s");
    }

    #[test]
    #[cfg(windows)]
    fn test_is_volume_root() {
        assert!(is_volume_root(Path::new("C:\\")));
        assert!(is_volume_root(Path::new("D:\\")));
        assert!(!is_volume_root(Path::new("C:\\Windows")));
        assert!(!is_volume_root(Path::new("C:\\Users\\test")));
    }

    #[test]
    fn test_extract_filename() {
        assert_eq!(
            extract_filename(Path::new("C:\\Users\\test\\file.txt")),
            "file.txt"
        );
        assert_eq!(
            extract_filename(Path::new("/home/user/document.pdf")),
            "document.pdf"
        );
    }
}