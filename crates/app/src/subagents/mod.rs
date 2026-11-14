//! Bounded current-format subagent records. Only the broker grants execution.
pub type PortFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, crate::AppError>> + Send + 'a>>;
mod branch;
mod chunk;
mod codec;
pub use branch::*;
pub use chunk::{CheckedBranchChunk, SubagentBranchCursor};
mod consent;
mod interaction;
mod journal;
mod queries;
pub use consent::verify_subagent_plan_consent;
pub use interaction::{AnalystPlanChoice, AnalystPlanInteraction, SafePlanPreview};
pub use journal::{
    BranchMaterialVerifier, SubagentJournal, TaskDispatchAttribution, is_subagent_kind,
};
pub use queries::{
    TaskEvidenceQueries, TaskEvidenceQuery, TaskEvidenceResult, VerifiedTaskQueryView,
};
mod plan;
pub use plan::{
    SubagentPlanApprovalV1, SubagentPlanContext, SubagentPlanDecision, SubagentPlanV1,
    SubagentPolicySnapshot, SubagentTaskSpec,
};
mod reservation;
mod resources;
mod result;
pub use reservation::{
    ReservationAction, ReservationPurpose, ReservationTransition, SubagentReservationV1,
};
pub use result::{SubagentCheckpointV1, SubagentResultV1, SubagentSourceRef, SubagentStatus};
mod sources;
mod storage;
pub use storage::{
    BoundedBranchBytes, BranchChunkRef, PublishedBranchChunk, StagedBranchChunk,
    SubagentBranchStore,
};
mod types;
pub use codec::{SubagentDigest, SubagentRecord, SubagentRecordError};
pub use resources::SubagentResources;
pub use sources::{SubagentSourcePageV1, SubagentSourceSetV1};
pub use types::{BundledSubagentType, SubagentTypeSnapshotV1, bundled_subagent_types};

#[derive(Clone)]
pub struct SubagentPorts {
    pub branches: std::sync::Arc<dyn SubagentBranchStore>,
    pub queries: std::sync::Arc<dyn TaskEvidenceQueries>,
    pub analyst: std::sync::Arc<dyn AnalystPlanInteraction>,
}

#[cfg(test)]
mod tests;
