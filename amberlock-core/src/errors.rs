use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("WinSec error: {0}")]
    WinSec(#[from] amberlock_winsec::error::WinSecError),
    #[error("Auth failed")]
    AuthFailed,
    #[error("Storage error: {0}")]
    Storage(#[from] anyhow::Error),
    #[error("Operation cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, CoreError>;
