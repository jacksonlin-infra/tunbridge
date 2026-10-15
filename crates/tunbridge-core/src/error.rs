#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(String),
    #[error("engine error: {0}")]
    Engine(String),
    #[error("discovery error: {0}")]
    Discovery(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("this operation requires an elevated (administrator) process")]
    NeedsElevation,
    #[error("tunbridge is not currently running")]
    NotRunning,
    #[error("already running: {0}")]
    AlreadyRunning(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
