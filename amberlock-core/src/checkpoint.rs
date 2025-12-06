//! 断点续执模块
//!
//! 支持大规模操作的进度保存和恢复，用于应对中断场景

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// 检查点数据
///
/// 记录操作的当前状态，用于中断恢复
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// 检查点ID（UUID）
    pub id: String,
    /// 操作类型（lock/unlock）
    pub operation: String,
    /// 创建时间
    pub created_at: String,
    /// 总对象数
    pub total_count: usize,
    /// 已处理索引
    pub processed_index: usize,
    /// 成功数
    pub succeeded: usize,
    /// 失败数
    pub failed: usize,
    /// 待处理路径列表（剩余部分）
    pub pending_paths: Vec<String>,
    /// 操作参数（JSON）
    pub operation_params: serde_json::Value,
}

impl Checkpoint {
    /// 创建新的检查点
    pub fn new(operation: &str, total_count: usize, params: serde_json::Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            total_count,
            processed_index: 0,
            succeeded: 0,
            failed: 0,
            pending_paths: Vec::new(),
            operation_params: params,
        }
    }

    /// 更新进度
    pub fn update_progress(
        &mut self,
        processed_index: usize,
        succeeded: usize,
        failed: usize,
        pending_paths: Vec<String>,
    ) {
        self.processed_index = processed_index;
        self.succeeded = succeeded;
        self.failed = failed;
        self.pending_paths = pending_paths;
    }

    /// 保存到文件
    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// 从文件加载
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let checkpoint: Checkpoint = serde_json::from_str(&json)?;
        Ok(checkpoint)
    }

    /// 计算完成百分比
    pub fn percentage(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            (self.processed_index as f64 / self.total_count as f64) * 100.0
        }
    }

    /// 是否已完成
    pub fn is_complete(&self) -> bool {
        self.processed_index >= self.total_count
    }
}

/// 检查点管理器
pub struct CheckpointManager {
    /// 检查点文件目录
    checkpoint_dir: PathBuf,
}

impl CheckpointManager {
    /// 创建检查点管理器
    ///
    /// # 参数
    /// - `checkpoint_dir`: 检查点文件存储目录
    pub fn new<P: AsRef<Path>>(checkpoint_dir: P) -> anyhow::Result<Self> {
        let dir = checkpoint_dir.as_ref().to_path_buf();

        // 确保目录存在
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
        }

        Ok(Self {
            checkpoint_dir: dir,
        })
    }

    /// 保存检查点
    pub fn save(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        let filename = format!("checkpoint-{}.json", checkpoint.id);
        let path = self.checkpoint_dir.join(filename);
        checkpoint.save(path)
    }

    /// 加载检查点
    pub fn load(&self, checkpoint_id: &str) -> anyhow::Result<Checkpoint> {
        let filename = format!("checkpoint-{}.json", checkpoint_id);
        let path = self.checkpoint_dir.join(filename);
        Checkpoint::load(path)
    }

    /// 删除检查点
    pub fn delete(&self, checkpoint_id: &str) -> anyhow::Result<()> {
        let filename = format!("checkpoint-{}.json", checkpoint_id);
        let path = self.checkpoint_dir.join(filename);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    /// 列出所有检查点
    pub fn list_checkpoints(&self) -> anyhow::Result<Vec<Checkpoint>> {
        let mut checkpoints = Vec::new();

        for entry in std::fs::read_dir(&self.checkpoint_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(checkpoint) = Checkpoint::load(&path) {
                    checkpoints.push(checkpoint);
                }
            }
        }

        // 按创建时间排序
        checkpoints.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(checkpoints)
    }

    /// 清理过期检查点（超过指定天数）
    pub fn cleanup_old_checkpoints(&self, days: u64) -> anyhow::Result<usize> {
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(days as i64);
        let mut deleted = 0;

        for checkpoint in self.list_checkpoints()? {
            if let Ok(created) = OffsetDateTime::parse(
                &checkpoint.created_at,
                &time::format_description::well_known::Rfc3339,
            ) {
                if created < cutoff {
                    self.delete(&checkpoint.id)?;
                    deleted += 1;
                }
            }
        }

        Ok(deleted)
    }
}

/// 检查点辅助宏
///
/// 简化检查点的保存和加载逻辑
#[macro_export]
macro_rules! checkpoint_save {
    ($manager:expr, $checkpoint:expr) => {
        if let Err(e) = $manager.save(&$checkpoint) {
            eprintln!("警告：保存检查点失败: {:?}", e);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_checkpoint_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let manager = CheckpointManager::new(temp_dir.path()).unwrap();

        let params = serde_json::json!({
            "mode": "lock",
            "level": "High"
        });

        let mut checkpoint = Checkpoint::new("lock", 100, params);
        checkpoint.update_progress(50, 45, 5, vec!["path1".into(), "path2".into()]);

        // 保存
        manager.save(&checkpoint).unwrap();

        // 加载
        let loaded = manager.load(&checkpoint.id).unwrap();

        assert_eq!(loaded.id, checkpoint.id);
        assert_eq!(loaded.processed_index, 50);
        assert_eq!(loaded.succeeded, 45);
        assert_eq!(loaded.failed, 5);
        assert_eq!(loaded.pending_paths.len(), 2);
    }

    #[test]
    fn test_checkpoint_percentage() {
        let params = serde_json::json!({});
        let mut checkpoint = Checkpoint::new("lock", 100, params);

        checkpoint.processed_index = 25;
        assert_eq!(checkpoint.percentage(), 25.0);

        checkpoint.processed_index = 100;
        assert!(checkpoint.is_complete());
    }

    #[test]
    fn test_list_checkpoints() {
        let temp_dir = tempdir().unwrap();
        let manager = CheckpointManager::new(temp_dir.path()).unwrap();

        // 创建多个检查点
        for i in 0..3 {
            let params = serde_json::json!({"index": i});
            let checkpoint = Checkpoint::new("test", 10, params);
            manager.save(&checkpoint).unwrap();
        }

        let checkpoints = manager.list_checkpoints().unwrap();
        assert_eq!(checkpoints.len(), 3);
    }

    #[test]
    fn test_delete_checkpoint() {
        let temp_dir = tempdir().unwrap();
        let manager = CheckpointManager::new(temp_dir.path()).unwrap();

        let params = serde_json::json!({});
        let checkpoint = Checkpoint::new("test", 10, params);
        let id = checkpoint.id.clone();

        manager.save(&checkpoint).unwrap();
        assert!(manager.load(&id).is_ok());

        manager.delete(&id).unwrap();
        assert!(manager.load(&id).is_err());
    }
}