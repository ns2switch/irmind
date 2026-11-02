use thiserror::Error;

/// Fixed or compile-time reasons only; never contains input text or credentials.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DefinitionError {
    #[error("policy denied: invalid or inconsistent signed parser definition")]
    InvalidSnapshot,
    #[error("policy denied: declarative definition history limit reached")]
    HistoryLimit,
    #[error("policy denied: active declarative definition limit reached")]
    ActiveLimit,
    #[error("policy denied: signed declarative definition version is unavailable")]
    VersionUnavailable,
    #[error("policy denied: parser preview exceeds its byte limit")]
    PreviewLimit,
    #[error("storage: parser definition storage is unavailable or invalid")]
    Storage,
    #[error("policy denied: {0}")]
    InvalidFormat(&'static str),
}
