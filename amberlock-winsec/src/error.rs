use thiserror::Error;

#[derive(Error, Debug)]
pub enum WinSecError {
    #[error("Win32 error {code}: {msg}")]
    Win32 { code: u32, msg: String },
    #[error("Privilege not held: {0}")]
    PrivilegeMissing(&'static str),
    #[error("Unsupported platform/operation")]
    Unsupported,
    #[error("Invalid label or SDDL")]
    InvalidLabel,
}
pub type Result<T> = std::result::Result<T, WinSecError>;
