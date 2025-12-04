//! 高级日志查询接口
//!
//! 提供类似 SQL 的查询能力，支持：
//! - 复合条件过滤（AND/OR）
//! - 分页和游标
//! - 排序（正序/倒序）
//! - 聚合统计

use serde_json::Value;
use std::path::Path;

use crate::NdjsonReader;

/// 查询构建器
///
/// # 示例
/// ```rust
/// let results = QueryBuilder::new("logs/operations.ndjson")
///     .filter_status("success")
///     .filter_time_after("2025-01-01T00:00:00Z")
///     .sort_desc()
///     .limit(100)
///     .execute()?;
/// ```
#[derive(Debug, Clone)]
pub struct QueryBuilder {
    file_path: String,
    filters: Vec<Filter>,
    sort_order: SortOrder,
    limit: Option<usize>,
    offset: usize,
}

/// 过滤条件
#[derive(Debug, Clone)]
enum Filter {
    /// 状态等于某值
    StatusEquals(String),
    /// 路径包含子串
    PathContains(String),
    /// 时间晚于某时刻
    TimeAfter(String),
    /// 时间早于某时刻
    TimeBefore(String),
    /// 用户 SID 等于某值
    UserSidEquals(String),
    /// 完整性级别等于某值
    LevelEquals(String),
    /// 自定义字段匹配
    CustomField { field: String, value: String },
}

/// 排序顺序
#[derive(Debug, Clone, Copy)]
pub enum SortOrder {
    /// 按时间正序（旧到新）
    Asc,
    /// 按时间倒序（新到旧）
    Desc,
    /// 保持文件顺序
    None,
}

impl QueryBuilder {
    /// 创建新的查询构建器
    pub fn new<P: AsRef<Path>>(file_path: P) -> Self {
        Self {
            file_path: file_path.as_ref().to_string_lossy().to_string(),
            filters: Vec::new(),
            sort_order: SortOrder::None,
            limit: None,
            offset: 0,
        }
    }

    /// 按状态过滤
    pub fn filter_status(mut self, status: &str) -> Self {
        self.filters.push(Filter::StatusEquals(status.to_string()));
        self
    }

    /// 按路径关键字过滤
    pub fn filter_path_contains(mut self, substr: &str) -> Self {
        self.filters.push(Filter::PathContains(substr.to_string()));
        self
    }

    /// 过滤时间晚于某时刻的记录
    pub fn filter_time_after(mut self, time: &str) -> Self {
        self.filters.push(Filter::TimeAfter(time.to_string()));
        self
    }

    /// 过滤时间早于某时刻的记录
    pub fn filter_time_before(mut self, time: &str) -> Self {
        self.filters.push(Filter::TimeBefore(time.to_string()));
        self
    }

    /// 按用户 SID 过滤
    pub fn filter_user_sid(mut self, sid: &str) -> Self {
        self.filters.push(Filter::UserSidEquals(sid.to_string()));
        self
    }

    /// 按完整性级别过滤
    pub fn filter_level(mut self, level: &str) -> Self {
        self.filters.push(Filter::LevelEquals(level.to_string()));
        self
    }

    /// 自定义字段过滤
    pub fn filter_custom(mut self, field: &str, value: &str) -> Self {
        self.filters.push(Filter::CustomField {
            field: field.to_string(),
            value: value.to_string(),
        });
        self
    }

    /// 设置按时间倒序排序
    pub fn sort_desc(mut self) -> Self {
        self.sort_order = SortOrder::Desc;
        self
    }

    /// 设置按时间正序排序
    pub fn sort_asc(mut self) -> Self {
        self.sort_order = SortOrder::Asc;
        self
    }

    /// 限制返回记录数
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// 设置偏移量（跳过前 N 条）
    pub fn offset(mut self, n: usize) -> Self {
        self.offset = n;
        self
    }

    /// 执行查询
    pub fn execute(self) -> anyhow::Result<Vec<Value>> {
        let mut reader = NdjsonReader::open(&self.file_path)?;

        // 读取所有行并解析为 JSON
        let all_records: Vec<Value> = reader
            .read_all_lines()?
            .into_iter()
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect();

        // 应用过滤器
        let filtered: Vec<Value> = all_records
            .into_iter()
            .filter(|record| self.apply_filters(record))
            .collect();

        // 排序
        let mut sorted = filtered;
        match self.sort_order {
            SortOrder::Asc => {
                sorted.sort_by(|a, b| {
                    let time_a = a.get("time_utc").and_then(|v| v.as_str()).unwrap_or("");
                    let time_b = b.get("time_utc").and_then(|v| v.as_str()).unwrap_or("");
                    time_a.cmp(time_b)
                });
            }
            SortOrder::Desc => {
                sorted.sort_by(|a, b| {
                    let time_a = a.get("time_utc").and_then(|v| v.as_str()).unwrap_or("");
                    let time_b = b.get("time_utc").and_then(|v| v.as_str()).unwrap_or("");
                    time_b.cmp(time_a)
                });
            }
            SortOrder::None => {}
        }

        // 分页
        let start = self.offset;
        let end = match self.limit {
            Some(limit) => (start + limit).min(sorted.len()),
            None => sorted.len(),
        };

        Ok(sorted[start..end].to_vec())
    }

    /// 内部方法：检查记录是否通过所有过滤器
    fn apply_filters(&self, record: &Value) -> bool {
        for filter in &self.filters {
            if !self.check_filter(record, filter) {
                return false;
            }
        }
        true
    }

    /// 内部方法：检查单个过滤器
    fn check_filter(&self, record: &Value, filter: &Filter) -> bool {
        match filter {
            Filter::StatusEquals(status) => {
                record
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(|s| s == status)
                    .unwrap_or(false)
            }
            Filter::PathContains(substr) => {
                record
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.contains(substr.as_str()))
                    .unwrap_or(false)
            }
            Filter::TimeAfter(time) => {
                record
                    .get("time_utc")
                    .and_then(|v| v.as_str())
                    .map(|s| s >= time.as_str())
                    .unwrap_or(false)
            }
            Filter::TimeBefore(time) => {
                record
                    .get("time_utc")
                    .and_then(|v| v.as_str())
                    .map(|s| s <= time.as_str())
                    .unwrap_or(false)
            }
            Filter::UserSidEquals(sid) => {
                record
                    .get("user_sid")
                    .and_then(|v| v.as_str())
                    .map(|s| s == sid)
                    .unwrap_or(false)
            }
            Filter::LevelEquals(level) => {
                record
                    .get("level_applied")
                    .and_then(|v| v.as_str())
                    .map(|s| s == level)
                    .unwrap_or(false)
            }
            Filter::CustomField { field, value } => {
                record
                    .get(field)
                    .and_then(|v| v.as_str())
                    .map(|s| s == value)
                    .unwrap_or(false)
            }
        }
    }
}

/// 日志统计信息
#[derive(Debug, Clone)]
pub struct LogStatistics {
    /// 总记录数
    pub total_count: usize,
    /// 成功操作数
    pub success_count: usize,
    /// 失败操作数
    pub error_count: usize,
    /// 待处理操作数
    pub pending_count: usize,
    /// 唯一用户 SID 数量
    pub unique_users: usize,
    /// 唯一路径数量
    pub unique_paths: usize,
}

/// 生成日志统计信息
///
/// # 示例
/// ```rust
/// let stats = generate_statistics("logs/operations.ndjson")?;
/// println!("总操作数: {}", stats.total_count);
/// println!("成功率: {:.2}%",
///     stats.success_count as f64 / stats.total_count as f64 * 100.0);
/// ```
pub fn generate_statistics<P: AsRef<Path>>(file_path: P) -> anyhow::Result<LogStatistics> {
    let mut reader = NdjsonReader::open(file_path)?;
    let all_lines = reader.read_all_lines()?;

    let mut stats = LogStatistics {
        total_count: 0,
        success_count: 0,
        error_count: 0,
        pending_count: 0,
        unique_users: 0,
        unique_paths: 0,
    };

    let mut users = std::collections::HashSet::new();
    let mut paths = std::collections::HashSet::new();

    for line in all_lines {
        if let Ok(record) = serde_json::from_str::<Value>(&line) {
            stats.total_count += 1;

            // 统计状态
            if let Some(status) = record.get("status").and_then(|v| v.as_str()) {
                match status {
                    "success" => stats.success_count += 1,
                    "error" => stats.error_count += 1,
                    "pending" => stats.pending_count += 1,
                    _ => {}
                }
            }

            // 收集唯一用户
            if let Some(user_sid) = record.get("user_sid").and_then(|v| v.as_str()) {
                users.insert(user_sid.to_string());
            }

            // 收集唯一路径
            if let Some(path) = record.get("path").and_then(|v| v.as_str()) {
                paths.insert(path.to_string());
            }
        }
    }

    stats.unique_users = users.len();
    stats.unique_paths = paths.len();

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NdjsonWriter;
    use tempfile::NamedTempFile;

    #[test]
    fn test_query_builder() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // 写入测试数据
        {
            let writer = NdjsonWriter::open_append(path).unwrap();
            for i in 0..20 {
                let record = serde_json::json!({
                    "id": format!("test-{}", i),
                    "status": if i % 3 == 0 { "error" } else { "success" },
                    "time_utc": format!("2025-01-{:02}T12:00:00Z", i + 1),
                    "path": format!("C:\\test\\file{}.txt", i),
                    "user_sid": if i < 10 { "S-1-5-21-USER1" } else { "S-1-5-21-USER2" },
                });
                writer.write_record(&record).unwrap();
            }
        }

        // 查询最近 5 条成功记录
        let results = QueryBuilder::new(path)
            .filter_status("success")
            .sort_desc()
            .limit(5)
            .execute()
            .unwrap();

        assert_eq!(results.len(), 5);
        assert!(results[0]["time_utc"].as_str().unwrap() > results[4]["time_utc"].as_str().unwrap());

        // 查询特定时间范围
        let results = QueryBuilder::new(path)
            .filter_time_after("2025-01-10T00:00:00Z")
            .filter_time_before("2025-01-15T23:59:59Z")
            .execute()
            .unwrap();

        assert!(results.len() > 0);
        assert!(results.len() <= 6); // 10-15日共6天
    }

    #[test]
    fn test_statistics() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // 写入测试数据
        {
            let writer = NdjsonWriter::open_append(path).unwrap();
            for i in 0..10 {
                let record = serde_json::json!({
                    "status": if i < 7 { "success" } else { "error" },
                    "user_sid": format!("S-1-5-21-USER{}", i % 3),
                    "path": format!("C:\\test\\file{}.txt", i % 5),
                });
                writer.write_record(&record).unwrap();
            }
        }

        let stats = generate_statistics(path).unwrap();

        assert_eq!(stats.total_count, 10);
        assert_eq!(stats.success_count, 7);
        assert_eq!(stats.error_count, 3);
        assert_eq!(stats.unique_users, 3);
        assert_eq!(stats.unique_paths, 5);
    }
}