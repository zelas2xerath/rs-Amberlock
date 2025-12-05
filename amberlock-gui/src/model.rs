//! 数据模型模块
//!
//! 提供文件列表和日志列表的数据模型，用于在Slint UI中显示和管理数据。
//! 模型负责数据的存储、转换和查询，并提供快照功能供UI组件绑定。

use amberlock_storage::NdjsonReader;
use once_cell::sync::Lazy;
use slint::{Model, ModelNotify, ModelTracker, SharedString, SharedVector, ToSharedString, ModelRc, VecModel};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

slint::include_modules!();

/// 文件列表项的内部表示结构
///
/// 包含文件路径和选中状态，使用元组形式存储以减少内存开销。
type FileEntry = (PathBuf, bool);

/// 全局选中的文件路径快照
///
/// 用于在模型销毁后仍能访问选中的文件路径列表。
/// 使用 `Lazy` 确保全局单例，`Mutex` 提供线程安全访问。
static SELECTED_SNAPSHOT: Lazy<Mutex<Vec<PathBuf>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// 文件列表模型
///
/// 用于管理用户选择的文件/文件夹列表，支持多选操作。
/// 模型内部使用 `Arc<Mutex<...>>` 包装，允许跨线程共享和UI数据绑定。
#[derive(Clone)]
pub struct FileListModel {
    /// 内部数据存储，使用互斥锁保护并发访问
    /// 元组包含：(文件路径, 是否选中)
    inner: Arc<Mutex<Vec<FileEntry>>>,
    /// 模型变更通知器，用于在数据变化时通知UI更新
    notify: Arc<ModelNotify>,
}

impl Default for FileListModel {
    fn default() -> Self {
        Self::new()
    }
}

impl FileListModel {
    /// 创建新的空文件列表模型
    ///
    /// # 示例
    ///
    /// ```rust
    /// let model = FileListModel::new();
    /// ```
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
            notify: Arc::new(ModelNotify::default()),
        }
    }

    /// 获取当前模型的快照，转换为Slint UI可用的格式
    ///
    /// # 返回值
    ///
    /// 返回 `SharedVector<FileItem>`，包含所有文件项的UI表示。
    /// 每个 `FileItem` 包含路径、类型、选中状态等信息。
    ///
    /// # 注意
    ///
    /// - 该方法会获取内部锁，阻塞直到锁可用
    /// - 路径类型根据 `Path::is_dir()` 判断
    /// - `il_text` 字段当前为空，未来可集成Windows安全描述符信息
    ///
    /// # 示例
    ///
    /// ```rust
    /// let snapshot = model.snapshot();
    /// ui.set_file_list(snapshot);
    /// ```
    pub fn snapshot(&self) -> SharedVector<FileItem> {
        // 获取内部数据的锁，如果锁被污染则panic（unwrap失败时）
        let entries = self.inner.lock().expect("FileListModel lock poisoned");

        // 预分配容量以减少重新分配
        let mut snapshot = SharedVector::with_capacity(entries.len());

        // 将内部数据转换为UI需要的格式
        for (path, selected) in entries.iter() {
            let item = FileItem {
                path: path_to_display_string(path),
                kind: file_kind_string(path),
                selected: *selected,
                il_text: SharedString::from(""), // 预留字段，可用于显示Windows完整性级别
            };
            snapshot.push(item);
        }

        snapshot
    }

    /// 添加文件/文件夹路径到模型
    ///
    /// # 参数
    ///
    /// - `paths`: 要添加的路径切片，路径会自动克隆存储
    /// - `selected`: 添加的路径是否默认为选中状态（默认为`true`）
    ///
    /// # 注意
    ///
    /// - 新添加的路径默认选中状态为`true`
    /// - 添加后会更新全局选中快照并通知UI更新
    /// - 不检查路径是否存在或重复，由调用方确保
    ///
    /// # 示例
    ///
    /// ```rust
    /// model.add_paths(&[PathBuf::from("/tmp/file.txt")]);
    /// ```
    pub fn add_paths(&self, paths: &[PathBuf]) {
        let mut entries = self.inner.lock().expect("FileListModel lock poisoned");

        // 记录添加前的行数，用于通知UI
        let old_len = entries.len();

        // 添加所有路径，默认选中状态为true
        for path in paths {
            entries.push((path.clone(), true));
        }

        // 更新全局选中快照
        Self::update_selected_snapshot(&entries);

        // 通知UI新增了行
        let new_len = entries.len();
        if new_len > old_len {
            self.notify.row_added(old_len, new_len - 1);
        }
    }

    /// 设置指定索引的选中状态
    ///
    /// # 参数
    ///
    /// - `index`: 要修改的项索引
    /// - `selected`: 新的选中状态
    ///
    /// # 返回值
    ///
    /// 成功返回`true`，索引越界返回`false`
    ///
    /// # 注意
    ///
    /// 修改选中状态后会更新全局选中快照并通知UI更新
    pub fn set_selected(&self, index: usize, selected: bool) -> bool {
        let mut entries = self.inner.lock().expect("FileListModel lock poisoned");

        if let Some((_, sel)) = entries.get_mut(index) {
            // 检查选中状态是否实际改变
            if *sel != selected {
                *sel = selected;
                Self::update_selected_snapshot(&entries);
                // 通知UI该行数据已更改
                self.notify.row_changed(index);
                true
            } else {
                // 状态未改变，无需通知
                true
            }
        } else {
            false
        }
    }

    /// 切换指定索引的选中状态
    ///
    /// # 参数
    ///
    /// - `index`: 要切换的项索引
    ///
    /// # 返回值
    ///
    /// 成功返回新的选中状态，索引越界返回`None`
    pub fn toggle_selected(&self, index: usize) -> Option<bool> {
        let mut entries = self.inner.lock().expect("FileListModel lock poisoned");

        if let Some((_, sel)) = entries.get_mut(index) {
            *sel = !*sel;
            let new_state = *sel;
            Self::update_selected_snapshot(&entries);
            // 通知UI该行数据已更改
            self.notify.row_changed(index);
            Some(new_state)
        } else {
            None
        }
    }

    /// 移除指定索引的项
    ///
    /// # 参数
    ///
    /// - `index`: 要移除的项索引
    ///
    /// # 返回值
    ///
    /// 成功返回被移除的路径，索引越界返回`None`
    ///
    /// # 注意
    ///
    /// 移除后会更新全局选中快照并通知UI更新
    pub fn remove_at(&self, index: usize) -> Option<PathBuf> {
        let mut entries = self.inner.lock().expect("FileListModel lock poisoned");

        if index < entries.len() {
            let removed = entries.remove(index);
            Self::update_selected_snapshot(&entries);
            // 通知UI该行已被移除
            self.notify.row_removed(index, index);
            Some(removed.0)
        } else {
            None
        }
    }

    /// 清空模型中的所有项
    ///
    /// # 注意
    ///
    /// 清空后会同时清空全局选中快照并通知UI更新
    pub fn clear(&self) {
        let mut entries = self.inner.lock().expect("FileListModel lock poisoned");

        if !entries.is_empty() {
            let old_len = entries.len();
            entries.clear();
            Self::update_selected_snapshot(&entries);
            // 通知UI所有行已被移除
            self.notify.row_removed(0, old_len - 1);
        }
    }

    /// 获取当前选中的文件路径列表
    ///
    /// # 返回值
    ///
    /// 包含所有选中项路径的向量
    ///
    /// # 注意
    ///
    /// 该方法会获取内部锁，建议缓存结果而非频繁调用
    pub fn selected_paths(&self) -> Vec<PathBuf> {
        let entries = self.inner.lock().expect("FileListModel lock poisoned");

        entries
            .iter()
            .filter(|(_, selected)| *selected)
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// 获取全局选中快照的路径列表
    ///
    /// # 返回值
    ///
    /// 全局选中快照的克隆
    ///
    /// # 注意
    ///
    /// 这是一个静态方法，可以在不持有模型实例的情况下获取选中路径
    /// 快照在每次选中状态变更时更新
    pub fn selected_paths_static() -> Vec<PathBuf> {
        SELECTED_SNAPSHOT
            .lock()
            .expect("SELECTED_SNAPSHOT lock poisoned")
            .clone()
    }

    /// 更新全局选中快照
    ///
    /// # 参数
    ///
    /// - `entries`: 当前模型的完整条目列表
    ///
    /// # 注意
    ///
    /// 内部方法，由其他修改选中状态的方法调用
    fn update_selected_snapshot(entries: &[FileEntry]) {
        let selected_paths: Vec<PathBuf> = entries
            .iter()
            .filter(|(_, selected)| *selected)
            .map(|(path, _)| path.clone())
            .collect();

        *SELECTED_SNAPSHOT
            .lock()
            .expect("SELECTED_SNAPSHOT lock poisoned") = selected_paths;
    }
}

/// 将路径转换为显示字符串
///
/// # 参数
///
/// - `path`: 文件系统路径
///
/// # 返回值
///
/// 路径的字符串表示，使用`to_string_lossy`处理无效Unicode
fn path_to_display_string(path: &Path) -> SharedString {
    path.to_string_lossy().to_shared_string()
}

/// 获取路径的类型字符串
///
/// # 参数
///
/// - `path`: 文件系统路径
///
/// # 返回值
///
/// - `"Directory"`: 路径指向目录
/// - `"File"`: 路径指向文件
/// - `"Unknown"`: 路径不存在或无法判断
///
/// # 注意
///
/// 该方法不会访问文件系统，仅根据路径后缀和约定判断
fn file_kind_string(path: &Path) -> SharedString {
    if path.is_dir() {
        "Directory".into()
    } else {
        "File".into()
    }
}

/// 为FileListModel实现Slint的Model trait，支持自动UI数据绑定和更新通知
impl Model for FileListModel {
    type Data = FileItem;

    /// 获取模型中的行数
    fn row_count(&self) -> usize {
        self.inner
            .lock()
            .expect("FileListModel lock poisoned")
            .len()
    }

    /// 获取指定行的数据
    ///
    /// # 参数
    ///
    /// - `row`: 行索引，从0开始
    ///
    /// # 返回值
    ///
    /// 如果索引有效则返回`Some(FileItem)`，否则返回`None`
    fn row_data(&self, row: usize) -> Option<Self::Data> {
        let entries = self.inner.lock().expect("FileListModel lock poisoned");

        entries.get(row).map(|(path, selected)| FileItem {
            path: path_to_display_string(path),
            kind: file_kind_string(path),
            selected: *selected,
            il_text: SharedString::from(""),
        })
    }

    /// 设置指定行的数据
    ///
    /// # 参数
    ///
    /// - `row`: 行索引，从0开始
    /// - `data`: 新的数据项
    ///
    /// # 注意
    ///
    /// 当前实现仅支持更新选中状态，其他字段会被忽略
    fn set_row_data(&self, row: usize, data: Self::Data) {
        let mut entries = self.inner.lock().expect("FileListModel lock poisoned");

        if let Some((_, selected)) = entries.get_mut(row) {
            // 只更新选中状态，保持路径不变
            if *selected != data.selected {
                *selected = data.selected;
                Self::update_selected_snapshot(&entries);
            }
        }
    }

    /// 获取模型跟踪器，用于在数据变化时通知UI
    ///
    /// # 返回值
    ///
    /// 返回一个`ModelTracker`，UI组件可以订阅模型变化
    fn model_tracker(&self) -> &dyn ModelTracker {
        self.notify.as_ref()
    }
}

/// 日志列表模型
///
/// 用于读取和显示Amberlock的NDJSON格式日志文件。
/// 支持分页读取、过滤和转换为UI格式。
#[derive(Clone, Debug)]
pub struct LogListModel {
    /// 日志文件路径
    path: String,
}

impl LogListModel {
    /// 打开指定路径的日志文件并创建模型
    ///
    /// # 参数
    ///
    /// - `path`: 日志文件路径
    ///
    /// # 返回值
    ///
    /// - `Ok(Self)`: 成功创建日志模型
    /// - `Err`: 路径无效或其他错误（当前实现总是成功）
    ///
    /// # 注意
    ///
    /// 当前实现不会验证文件是否存在或可读
    pub fn open(path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            path: path.to_string(),
        })
    }

    /// 获取日志快照，返回最新的若干条记录
    ///
    /// # 参数
    ///
    /// - `limit`: 最大返回记录数
    ///
    /// # 返回值
    ///
    /// 包含日志记录的`SharedVector<LogRow>`，按时间倒序排列
    ///
    /// # 注意
    ///
    /// - 如果文件打开或读取失败，返回空向量
    /// - 使用`NdjsonReader::read_last_n`获取最新记录
    /// - 字段缺失时使用空字符串替代
    pub fn snapshot(&self, limit: usize) -> SharedVector<LogRow> {
        self.read_and_map_logs(|reader| reader.read_last_n(limit), limit)
    }

    /// 获取过滤后的日志快照
    ///
    /// # 参数
    ///
    /// - `query`: 过滤查询字符串
    /// - `limit`: 最大返回记录数
    ///
    /// # 返回值
    ///
    /// 包含匹配查询的日志记录的`SharedVector<LogRow>`
    ///
    /// # 注意
    ///
    /// - 查询逻辑由`NdjsonReader::filter`实现
    /// - 如果过滤失败，返回空向量
    pub fn filter_snapshot(&self, query: &str, limit: usize) -> SharedVector<LogRow> {
        self.read_and_map_logs(|reader| reader.filter(query, limit), limit)
    }

    /// 内部方法：读取日志并映射到UI格式
    ///
    /// # 参数
    ///
    /// - `read_operation`: 读取操作闭包，接受`&mut NdjsonReader`，返回`anyhow::Result<Vec<serde_json::Value>>`
    /// - `capacity_hint`: 容量提示，用于预分配向量空间
    ///
    /// # 返回值
    ///
    /// 映射后的日志记录向量
    fn read_and_map_logs<F>(&self, read_operation: F, capacity_hint: usize) -> SharedVector<LogRow>
    where
        F: FnOnce(&mut NdjsonReader) -> anyhow::Result<Vec<serde_json::Value>>,
    {
        // 尝试打开日志文件
        let mut reader = match NdjsonReader::open(&self.path) {
            Ok(reader) => reader,
            Err(_) => return SharedVector::default(),
        };

        // 执行读取操作
        let log_values = match read_operation(&mut reader) {
            Ok(values) => values,
            Err(_) => return SharedVector::default(),
        };

        // 预分配空间以提高性能
        let mut snapshot = SharedVector::with_capacity(log_values.len().min(capacity_hint));

        // 将JSON值映射到LogRow结构
        for value in log_values {
            let row = self.map_json_to_logrow(&value);
            snapshot.push(row);
        }

        snapshot
    }

    /// 将JSON值映射到LogRow结构
    ///
    /// # 参数
    ///
    /// - `value`: 单条日志的JSON表示
    ///
    /// # 返回值
    ///
    /// 转换后的`LogRow`，缺失字段用空字符串填充
    fn map_json_to_logrow(&self, value: &serde_json::Value) -> LogRow {
        LogRow {
            time: value
                .get("time_utc")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
            action: value
                .get("status") // 注意：原代码使用status作为action，可能是字段名不一致
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
            path: value
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
            level: value
                .get("level_applied")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
            status: value
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
        }
    }
}
