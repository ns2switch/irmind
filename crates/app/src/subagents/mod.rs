//! Bounded current-format subagent records. Only the broker grants execution.
mod branch;
mod chunk;
mod codec;
pub use branch::*;
pub use chunk::{CheckedBranchChunk, SubagentBranchCursor};
mod consent;
pub use consent::verify_subagent_plan_consent;
mod plan;
pub use plan::{
    SubagentPlanApprovalV1, SubagentPlanContext, SubagentPlanDecision, SubagentPlanV1,
    SubagentPolicySnapshot, SubagentTaskSpec,
};
mod reservation;
mod resources;
mod result;
pub use reservation::{ReservationAction, ReservationPurpose, SubagentReservationV1};
pub use result::{SubagentCheckpointV1, SubagentResultV1, SubagentSourceRef, SubagentStatus};
mod sources;
mod types;
pub use codec::{SubagentDigest, SubagentRecord, SubagentRecordError};
pub use resources::SubagentResources;
pub use sources::{SubagentSourcePageV1, SubagentSourceSetV1};
pub use types::{BundledSubagentType, SubagentTypeSnapshotV1, bundled_subagent_types};

#[cfg(test)]
mod tests;
