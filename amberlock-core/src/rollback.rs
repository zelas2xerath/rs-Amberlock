//! 回滚机制模块
//!
//! 提供操作前状态记录和失败时的回滚功能

use amberlock_types::{LabelLevel, MandPolicy, Result };
use amberlock_winsec as winsec;
use std::path::PathBuf;

/// 单个对象的备份信息
#[derive(Debug, Clone)]
pub struct ObjectBackup {
    /// 路径
    pub path: PathBuf,
    /// 原始 SDDL（包含 Mandatory Label）
    pub original_sddl: Option<String>,
    /// 原始完整性级别
    pub original_level: Option<LabelLevel>,
    /// 原始策略
    pub original_policy: Option<MandPolicy>,
}

/// 回滚管理器
///
/// 记录所有已修改对象的原始状态，支持批量回滚
pub struct RollbackManager {
    /// 备份列表（按操作顺序）
    backups: Vec<ObjectBackup>,
    /// 是否启用自动回滚
    auto_rollback: bool,
}

impl RollbackManager {
    /// 创建新的回滚管理器
    ///
    /// # 参数
    /// - `auto_rollback`: 析构时是否自动回滚（用于 RAII 模式）
    pub fn new(auto_rollback: bool) -> Self {
        Self {
            backups: Vec::new(),
            auto_rollback,
        }
    }

    /// 记录对象的当前状态（操作前备份）
    ///
    /// # 参数
    /// - `path`: 要备份的对象路径
    ///
    /// # 返回
    /// - `Ok(())`: 备份成功
    /// - `Err`: 读取对象状态失败
    pub fn backup(&mut self, path: &str) -> Result<()> {
        // 读取当前标签状态
        let label_info = winsec::get_object_label(path).ok();

        let backup = ObjectBackup {
            path: PathBuf::from(path),
            original_sddl: label_info.as_ref().map(|l| l.sddl.clone()),
            original_level: label_info.as_ref().map(|l| l.level),
            original_policy: label_info.as_ref().map(|l| l.policy),
        };

        self.backups.push(backup);
        Ok(())
    }

    /// 批量备份多个对象
    pub fn backup_batch(&mut self, paths: &[PathBuf]) -> Result<()> {
        for path in paths {
            // 忽略单个备份失败，继续处理其他对象
            let _ = self.backup(&path.to_string_lossy());
        }
        Ok(())
    }

    /// 执行回滚操作
    ///
    /// # 策略
    /// - 倒序恢复（先恢复最后修改的对象）
    /// - 部分失败不影响其他对象
    ///
    /// # 返回
    /// 包含成功和失败计数的结果
    pub fn rollback(&mut self) -> RollbackResult {
        let mut result = RollbackResult {
            total: self.backups.len(),
            succeeded: 0,
            failed: 0,
        };

        // 倒序恢复
        for backup in self.backups.iter().rev() {
            match self.restore_single(backup) {
                Ok(_) => result.succeeded += 1,
                Err(_) => result.failed += 1,
            }
        }

        // 清空备份列表
        self.backups.clear();

        result
    }

    /// 恢复单个对象
    fn restore_single(&self, backup: &ObjectBackup) -> Result<()> {
        let path = backup.path.to_string_lossy();

        if let Some(original_level) = backup.original_level {
            if let Some(original_policy) = backup.original_policy {
                // 恢复原始标签
                winsec::set_mandatory_label(&path, original_level, original_policy)?;
            } else {
                // 没有原始策略，移除标签
                winsec::remove_mandatory_label(&path)?;
            }
        } else {
            // 没有原始级别，移除标签
            winsec::remove_mandatory_label(&path)?;
        }

        Ok(())
    }

    /// 禁用自动回滚（用于操作成功后）
    pub fn commit(&mut self) {
        self.auto_rollback = false;
        self.backups.clear();
    }

    /// 获取备份数量
    pub fn backup_count(&self) -> usize {
        self.backups.len()
    }

    /// 检查是否有备份
    pub fn has_backups(&self) -> bool {
        !self.backups.is_empty()
    }
}

impl Drop for RollbackManager {
    fn drop(&mut self) {
        // 如果启用自动回滚且有备份，执行回滚
        if self.auto_rollback && !self.backups.is_empty() {
            let _ = self.rollback();
        }
    }
}

/// 回滚结果统计
#[derive(Debug, Clone)]
pub struct RollbackResult {
    /// 总对象数
    pub total: usize,
    /// 成功恢复数
    pub succeeded: usize,
    /// 失败数
    pub failed: usize,
}

impl RollbackResult {
    /// 是否完全成功
    pub fn is_complete_success(&self) -> bool {
        self.failed == 0 && self.succeeded == self.total
    }

    /// 是否部分成功
    pub fn is_partial_success(&self) -> bool {
        self.succeeded > 0 && self.failed > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollback_manager_basic() {
        let mut manager = RollbackManager::new(false);

        assert_eq!(manager.backup_count(), 0);
        assert!(!manager.has_backups());

        // 备份（会失败但不影响测试逻辑）
        let _ = manager.backup("C:\\nonexistent\\path");
        assert_eq!(manager.backup_count(), 1);
    }

    #[test]
    fn test_auto_rollback_disabled_on_commit() {
        let mut manager = RollbackManager::new(true);
        let _ = manager.backup("C:\\test");

        manager.commit();

        // commit 后自动回滚被禁用，且备份清空
        assert_eq!(manager.backup_count(), 0);
    }

    #[test]
    fn test_rollback_result() {
        let result = RollbackResult {
            total: 10,
            succeeded: 10,
            failed: 0,
        };
        assert!(result.is_complete_success());
        assert!(!result.is_partial_success());

        let partial = RollbackResult {
            total: 10,
            succeeded: 7,
            failed: 3,
        };
        assert!(!partial.is_complete_success());
        assert!(partial.is_partial_success());
    }
}
