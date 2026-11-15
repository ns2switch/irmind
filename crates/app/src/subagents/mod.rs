//! Bounded current-format subagent records. Only the broker grants execution.
pub type PortFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, crate::AppError>> + Send + 'a>>;
mod branch;
mod broker;
pub use broker::{PreparedSubagentPlan, StartedSubagentPlan, SubagentTaskProposal};
mod chunk;
mod codec;
pub use branch::*;
pub use chunk::{CheckedBranchChunk, SubagentBranchCursor};
mod consent;
mod events;
mod finding;
pub use events::{
    EngineEvent, EngineEventBatch, EngineEventKind, EngineEventSubscription, EventCursor,
};
mod interaction;
mod journal;
mod queries;
pub use consent::verify_subagent_plan_consent;
pub use interaction::{
    AnalystPlanChoice, AnalystPlanInteraction, AnalystPlanMailbox, PlanReview, SafePlanPreview,
};
pub use journal::{
    BranchMaterialVerifier, SubagentJournal, TaskDispatchAttribution, is_subagent_kind,
};
pub use queries::{
    TaskEvidenceQueries, TaskEvidenceQuery, TaskEvidenceResult, TaskQueryPartialReason,
    VerifiedTaskQueryView,
};
mod pending;
mod plan;
pub(crate) mod runtime;
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

impl crate::Engine<'_> {
    pub(crate) fn turn_model_rounds_unlocked(
        &self,
        case: &crate::CaseId,
        turn: &str,
    ) -> Result<u64, crate::AppError> {
        let mut journal = SubagentJournal::for_verification(case.clone())
            .map_err(|_| crate::AppError::InvalidChain(0))?;
        for entry in self.audit_log.entries(case)? {
            journal.accept(&entry, self.verifier.as_ref())?;
        }
        journal
            .rounds_used(turn)
            .map_err(|_| crate::AppError::InvalidChain(0))
    }

    pub(crate) fn subagent_holds_unlocked(
        &self,
        case: &crate::CaseId,
    ) -> Result<SubagentResources, crate::AppError> {
        let entries = self.audit_log.entries(case)?;
        if !entries.iter().any(|entry| is_subagent_kind(entry.kind)) {
            return Ok(SubagentResources::default());
        }
        let mut journal = SubagentJournal::for_verification(case.clone())
            .map_err(|_| crate::AppError::InvalidChain(0))?;
        for entry in &entries {
            journal.accept(entry, self.verifier.as_ref())?;
        }
        journal
            .outstanding()
            .map_err(|_| crate::AppError::InvalidChain(0))
    }

    pub(crate) fn require_no_active_subagents(
        &self,
        case: &crate::CaseId,
    ) -> Result<(), crate::AppError> {
        let entries = self.audit_log.entries(case)?;
        if !entries.iter().any(|entry| is_subagent_kind(entry.kind)) {
            return Ok(());
        }
        let mut journal = SubagentJournal::for_verification(case.clone())
            .map_err(|_| crate::AppError::InvalidChain(0))?;
        for entry in &entries {
            journal.accept(entry, self.verifier.as_ref())?;
        }
        if journal
            .has_open_plans()
            .map_err(|_| crate::AppError::InvalidChain(0))?
        {
            return Err(crate::AppError::Policy(
                "Subagent plan is still active; cancel or finish it before sealing".into(),
            ));
        }
        Ok(())
    }
}
