mod audit;
mod local;
mod model;
mod remote;

pub use audit::{
    AppError, CancelledOperation, CaseSeal, GLOBAL_OPERATION_SCOPE, SignedEntry, SignedOperation,
    hex, seal_challenge, sha256,
};
pub(crate) use audit::{isolate_untrusted, remote_tool_error, run_async, safe_markdown};
pub use local::{
    AuditLog, CaseExporter, CaseLock, CaseMutation, Clock, ContentGuard, EventParser,
    EvidenceGraph, EvidenceStore, ExportVerification, ExportVerifier, LargeCaseExporter,
    LargeCaseStore, PreparedSource, Repository, Screened, Signer, StreamingEventParser, Verifier,
    startup_check,
};
pub use model::{
    CompletionMessage, CompletionRequest, LlmPort, MessageRole, ModelEvent, ModelPricing,
    ModelResponse, ModelStream, ModelUsage, UsageEvent, collect_model_stream,
    collect_model_stream_with_progress, single_completion_stream, summarize_usage,
};
pub use remote::{CloudAuditPort, EdrPort, InternalIntelPort, SiemPort, ThreatIntelPort};
