//! AmberLock 存储模块
//!
//! 提供基于 NDJSON (JSON Lines) 格式的日志持久化和设置管理。
//!
//! # 核心功能
//! - **日志写入**：线程安全的追加写入，支持任意可序列化类型
//! - **日志读取**：支持尾部读取、关键字过滤、时间区间查询
//! - **设置管理**：简单的 JSON 配置文件读写
//! - **高级查询**：类 SQL 的复合条件查询和统计分析
//!
//! # NDJSON 格式说明
//! 每行一个完整的 JSON 对象，无需数组包装，适合流式追加和大文件处理。
//!
//! 示例：
//! ```json
//! {"id":"uuid1","time_utc":"2025-01-01T00:00:00Z","status":"success"}
//! {"id":"uuid2","time_utc":"2025-01-01T01:00:00Z","status":"error"}
//! ```

pub mod query;

use amberlock_types::Settings;
use anyhow::Result;
use parking_lot::Mutex;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::Path,
};

// ================================
// NDJSON 写入器
// ================================

/// 线程安全的 NDJSON 日志写入器
///
/// 支持多线程并发写入，自动追加模式，每条记录占据一行。
pub struct NdjsonWriter {
    /// 内部文件句柄，使用互斥锁保护并发访问
    file: Mutex<BufWriter<File>>,
}

impl NdjsonWriter {
    /// 以追加模式打开日志文件
    ///
    /// # 参数
    /// - `path`: 日志文件路径，如果不存在会自动创建
    ///
    /// # 返回
    /// - `Ok(Self)`: 成功打开的写入器
    /// - `Err`: 文件打开失败（权限不足、路径无效等）
    ///
    /// # 示例
    /// ```rust
    /// let writer = NdjsonWriter::open_append("logs/operations.ndjson")?;
    /// ```
    pub fn open_append<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true) // 文件不存在时创建
            .append(true) // 追加模式，不覆盖现有内容
            .open(path)?;

        Ok(Self {
            file: Mutex::new(BufWriter::new(file)),
        })
    }

    /// 写入单条记录
    ///
    /// # 参数
    /// - `rec`: 任意可序列化的记录（通常是 `LockRecord` 或 `Settings`）
    ///
    /// # 返回
    /// - `Ok(())`: 写入成功
    /// - `Err`: 序列化失败或 IO 错误
    ///
    /// # 注意
    /// - 自动在每条记录后添加换行符
    /// - 不会自动刷新缓冲区，需要手动调用 `flush()` 或依赖析构
    ///
    /// # 示例
    /// ```rust
    /// let record = LockRecord { id: "test".into(), ... };
    /// writer.write_record(&record)?;
    /// ```
    pub fn write_record<T: serde::Serialize>(&self, rec: &T) -> Result<()> {
        let mut guard = self.file.lock();

        // 序列化为 JSON 字符串
        let json_line = serde_json::to_string(rec)?;

        // 写入一行：JSON + 换行符
        writeln!(guard, "{}", json_line)?;

        Ok(())
    }

    /// 强制刷新缓冲区到磁盘
    ///
    /// # 返回
    /// - `Ok(())`: 刷新成功
    /// - `Err`: IO 错误
    ///
    /// # 使用场景
    /// - 关键操作后确保数据持久化
    /// - 定时刷新（如每秒一次）
    /// - 程序退出前
    pub fn flush(&self) -> Result<()> {
        let mut guard = self.file.lock();
        guard.flush()?;
        Ok(())
    }
}

// 实现 Drop trait，确保程序退出时刷新缓冲区
impl Drop for NdjsonWriter {
    fn drop(&mut self) {
        // 尽力刷新，忽略错误（析构时无法传播错误）
        let _ = self.file.lock().flush();
    }
}

// ================================
// NDJSON 读取器
// ================================

/// NDJSON 日志读取器
///
/// 提供日志查询、过滤和分页功能。
pub struct NdjsonReader {
    /// 内部文件句柄，使用 BufReader 提升读取性能
    file: BufReader<File>,
}

impl NdjsonReader {
    /// 打开日志文件用于读取
    ///
    /// # 参数
    /// - `path`: 日志文件路径
    ///
    /// # 返回
    /// - `Ok(Self)`: 成功打开的读取器
    /// - `Err`: 文件不存在或无权限
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        Ok(Self {
            file: BufReader::new(file),
        })
    }

    /// 读取文件末尾最后 N 条记录
    ///
    /// # 参数
    /// - `n`: 要读取的最大记录数
    ///
    /// # 返回
    /// - `Ok(Vec<serde_json::Value>)`: 成功读取的记录列表（按文件顺序，最新在后）
    /// - `Err`: IO 错误或 JSON 解析错误
    ///
    /// # 实现策略
    /// 1. 先读取全部行（对大文件性能较差，可优化为倒序读取）
    /// 2. 取最后 N 行
    /// 3. 解析为 JSON
    ///
    /// # 示例
    /// ```rust
    /// let mut reader = NdjsonReader::open("logs/operations.ndjson")?;
    /// let recent_logs = reader.read_last_n(100)?; // 最近 100 条
    /// ```
    pub fn read_last_n(&mut self, n: usize) -> Result<Vec<serde_json::Value>> {
        // 读取所有行
        let all_lines = self.read_all_lines()?;

        // 计算起始索引（避免负数）
        let start_index = all_lines.len().saturating_sub(n);

        // 取最后 N 行并解析
        let result: Result<Vec<_>, _> = all_lines[start_index..]
            .iter()
            .map(|line| serde_json::from_str(line))
            .collect();

        Ok(result?)
    }

    /// 按关键字过滤日志记录
    ///
    /// # 参数
    /// - `key_substr`: 关键字子串（不区分大小写）
    /// - `limit`: 最大返回记录数
    ///
    /// # 返回
    /// - `Ok(Vec<serde_json::Value>)`: 匹配的记录列表
    /// - `Err`: IO 错误或 JSON 解析错误
    ///
    /// # 匹配规则
    /// - 对整行 JSON 文本进行子串匹配（包含路径、状态、错误信息等）
    /// - 不区分大小写
    /// - 从文件开头向后扫描，找到 `limit` 条后停止
    ///
    /// # 示例
    /// ```rust
    /// // 查找所有失败的操作
    /// let errors = reader.filter("error", 50)?;
    ///
    /// // 查找特定路径的日志
    /// let path_logs = reader.filter("C:\\Users\\test", 100)?;
    /// ```
    pub fn filter(
        &mut self,
        key_substr: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let all_lines = self.read_all_lines()?;
        let key_lower = key_substr.to_lowercase();

        let result: Result<Vec<_>, _> = all_lines
            .iter()
            .filter(|line| line.to_lowercase().contains(&key_lower))
            .take(limit)
            .map(|line| serde_json::from_str(line))
            .collect();

        Ok(result?)
    }

    /// 按时间区间过滤日志（高级功能）
    ///
    /// # 参数
    /// - `start`: 起始时间（ISO8601 格式，如 "2025-01-01T00:00:00Z"）
    /// - `end`: 结束时间（同上）
    /// - `limit`: 最大返回记录数
    ///
    /// # 返回
    /// - `Ok(Vec<serde_json::Value>)`: 匹配的记录列表
    /// - `Err`: 时间解析错误或 IO 错误
    ///
    /// # 注意
    /// - 假设记录中包含 `time_utc` 字段
    /// - 时间比较使用字符串字典序（ISO8601 格式支持）
    pub fn filter_by_time_range(
        &mut self,
        start: &str,
        end: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let all_lines = self.read_all_lines()?;

        let result: Result<Vec<_>, _> = all_lines
            .iter()
            .filter_map(|line| {
                // 尝试解析 JSON
                serde_json::from_str::<serde_json::Value>(line).ok()
            })
            .filter(|json| {
                // 提取 time_utc 字段并进行时间范围判断
                if let Some(time_utc) = json.get("time_utc").and_then(|v| v.as_str()) {
                    time_utc >= start && time_utc <= end
                } else {
                    false
                }
            })
            .take(limit)
            .map(|item| Ok(item))
            .collect::<Result<Vec<_>>>();

        Ok(result?)
    }

    /// 按状态过滤日志（便捷方法）
    ///
    /// # 参数
    /// - `status`: 状态字符串（如 "success", "error", "pending"）
    /// - `limit`: 最大返回记录数
    ///
    /// # 示例
    /// ```rust
    /// let failed_ops = reader.filter_by_status("error", 100)?;
    /// ```
    pub fn filter_by_status(
        &mut self,
        status: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let all_lines = self.read_all_lines()?;

        let result: Result<Vec<_>, _> = all_lines
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|json| {
                json.get("status")
                    .and_then(|v| v.as_str())
                    .map(|s| s == status)
                    .unwrap_or(false)
            })
            .take(limit)
            .map(|item| Ok(item))
            .collect::<Result<Vec<_>>>();

        Ok(result?)
    }

    /// 统计日志记录总数（行数）
    ///
    /// # 返回
    /// - `Ok(usize)`: 记录总数
    /// - `Err`: IO 错误
    pub fn count_records(&mut self) -> Result<usize> {
        Ok(self.read_all_lines()?.len())
    }

    /// 内部方法：读取文件所有行
    ///
    /// # 注意
    /// - 会重置文件指针到开头
    /// - 对大文件可能消耗大量内存，未来可优化为流式处理
    ///
    /// # 可见性
    /// pub(crate) 允许 query 模块访问，但不对外暴露
    pub(crate) fn read_all_lines(&mut self) -> Result<Vec<String>> {
        // 重置文件指针到开头
        self.file.seek(SeekFrom::Start(0))?;

        let mut lines = Vec::new();
        let mut buffer = String::new();

        loop {
            buffer.clear();
            let bytes_read = self.file.read_line(&mut buffer)?;

            if bytes_read == 0 {
                break; // 文件结束
            }

            // 去除行尾换行符并存储
            let trimmed = buffer.trim_end().to_string();
            if !trimmed.is_empty() {
                lines.push(trimmed);
            }
        }

        Ok(lines)
    }
}

// ================================
// 设置管理
// ================================

/// 从文件加载应用程序设置
///
/// # 参数
/// - `path`: 设置文件路径（JSON 格式）
///
/// # 返回
/// - `Ok(Settings)`: 成功加载的设置对象
/// - `Err`: 文件不存在、JSON 格式错误或反序列化失败
///
/// # 示例
/// ```rust
/// let settings = load_settings("config/amberlock-settings.json")?;
/// println!("并行度: {}", settings.parallelism);
/// ```
pub fn load_settings<P: AsRef<Path>>(path: P) -> Result<Settings> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let settings: Settings = serde_json::from_reader(reader)?;
    Ok(settings)
}

/// 将应用程序设置保存到文件
///
/// # 参数
/// - `path`: 设置文件路径
/// - `s`: 要保存的设置对象
///
/// # 返回
/// - `Ok(())`: 保存成功
/// - `Err`: 文件写入失败或序列化错误
///
/// # 注意
/// - 会覆盖现有文件
/// - 自动创建父目录（如果实现）
///
/// # 示例
/// ```rust
/// let mut settings = load_settings("config.json")?;
/// settings.parallelism = 8;
/// save_settings("config.json", &settings)?;
/// ```
pub fn save_settings<P: AsRef<Path>>(path: P, s: &Settings) -> Result<()> {
    // 如果父目录不存在，尝试创建（可选功能）
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(path)?;
    let writer = BufWriter::new(file);

    // 使用漂亮的 JSON 格式（便于人工编辑）
    serde_json::to_writer_pretty(writer, s)?;

    Ok(())
}

// ================================
// 测试
// ================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_write_and_read_records() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // 写入测试记录
        {
            let writer = NdjsonWriter::open_append(path).unwrap();

            for i in 0..10 {
                let record = serde_json::json!({
                    "id": format!("test-{}", i),
                    "status": if i % 2 == 0 { "success" } else { "error" },
                    "time_utc": format!("2025-01-01T{:02}:00:00Z", i),
                });
                writer.write_record(&record).unwrap();
            }
            writer.flush().unwrap();
        }

        // 读取最后 3 条记录
        {
            let mut reader = NdjsonReader::open(path).unwrap();
            let records = reader.read_last_n(3).unwrap();

            assert_eq!(records.len(), 3);
            assert_eq!(records[2]["id"], "test-9");
        }

        // 过滤 error 状态
        {
            let mut reader = NdjsonReader::open(path).unwrap();
            let errors = reader.filter("error", 10).unwrap();

            assert_eq!(errors.len(), 5); // 5 条 error 记录
        }

        // 统计总数
        {
            let mut reader = NdjsonReader::open(path).unwrap();
            let count = reader.count_records().unwrap();

            assert_eq!(count, 10);
        }
    }

    #[test]
    fn test_settings_round_trip() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let original_settings = Settings {
            parallelism: 4,
            default_mode: amberlock_types::ProtectMode::ReadOnly,
            default_level: amberlock_types::LabelLevel::High,
            enable_nr_nx: false,
            log_path: "/var/log/amberlock.ndjson".to_string(),
            vault_path: "/var/lib/amberlock/vault.bin".to_string(),
            shell_integration: false,
        };

        // 保存
        save_settings(path, &original_settings).unwrap();

        // 加载
        let loaded_settings = load_settings(path).unwrap();

        // 验证
        assert_eq!(loaded_settings.parallelism, 4);
        assert_eq!(loaded_settings.default_mode, amberlock_types::ProtectMode::ReadOnly);
        assert_eq!(loaded_settings.log_path, "/var/log/amberlock.ndjson");
    }
}
