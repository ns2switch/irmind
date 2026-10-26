use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdapterGuardError {
    #[error("content guard: content exceeds guard limit")]
    ContentExceedsGuardLimit,
    #[error("content guard: startup injection corpus failed")]
    StartupInjectionCorpusFailed,
    #[error("content guard: startup private-key self-test failed")]
    StartupPrivateKeySelfTestFailed,
    #[error("content guard: startup redaction self-test failed")]
    StartupRedactionSelfTestFailed,
}
