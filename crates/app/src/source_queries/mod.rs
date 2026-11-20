//! Bounded, principal-only source-query admission. Providers never grant authority.
mod admission;
mod broker;
mod canonical;
mod capture;
mod compile;
mod completion;
mod export;
mod ports;
mod receipts;
#[cfg(test)]
mod tests;
mod types;
pub use admission::{SignedSourceQueryAdmission, SourceQueryAuthority};
pub use broker::{SourceQueryBroker, SourceQueryHold, SourceQueryResources};
pub use canonical::{canonical_query_json, query_content_id};
pub use capture::{CaptureError, QueryCaptureSummary, verify_query_capture};
pub use compile::*;
pub use completion::{
    SignedSourceQuerySettlement, SourceQueryExecutionV1, SourceQueryResultV1,
    SourceQuerySettlementV1,
};
pub use export::verify_query_capture_section;
pub use ports::*;
pub(crate) use receipts::BudgetReplay;
pub use receipts::{
    SourceQueryApprovalV1, SourceQueryBudgetV1, SourceQueryPlanV1, SourceQueryReservationV1,
};
pub use types::*;

pub const QUERY_MAX_RECORD_BYTES: usize = 128 * 1024;
pub const QUERY_MAX_ROWS: u64 = 100_000;
pub const QUERY_MAX_BYTES: u64 = 100_000_000;
pub const QUERY_CASE_MAX_ROWS: u64 = 1_000_000;
pub const QUERY_CASE_MAX_BYTES: u64 = 1_000_000_000;
pub const QUERY_DEFAULT_INTERVAL_SECONDS: u64 = 31 * 86_400;
pub const QUERY_MAX_INTERVAL_SECONDS: u64 = 366 * 86_400;
pub const QUERY_MAX_PAGES: u64 = 4096;
pub const QUERY_CAPTURE_MAGIC: &[u8] = b"IRMIND-QUERY-CAPTURE-V1\0";

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceQueryError {
    #[error("invalid or noncanonical source-query data")]
    Invalid,
    #[error("source-query limit exceeded")]
    Limit,
    #[error("source queries are unavailable for subagents in this version")]
    Subagent,
    #[error(
        "source-query allocation is disabled; ask the analyst to configure /budget within the organization ceiling"
    )]
    Disabled,
    #[error("source query exceeds case or organization scope")]
    Scope,
    #[error("source-query scan or retention budget exhausted; use /budget")]
    Budget,
    #[error("source-query approval does not match the exact plan")]
    Approval,
    #[error("source-query execution outcome remains unresolved; reconcile it before retrying")]
    Unresolved,
    #[error("source-query reservation has already been settled")]
    AlreadySettled,
    #[error("source-query field or operator has no exact translation")]
    Unsupported,
    #[error("source-query module is unavailable")]
    Unavailable,
}
impl From<SourceQueryError> for crate::AppError {
    fn from(value: SourceQueryError) -> Self {
        Self::Policy(value.to_string())
    }
}
