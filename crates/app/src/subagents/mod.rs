//! Bounded current-format subagent records. Only the broker grants execution.
mod codec;
mod plan;
pub use plan::{
    SubagentPlanApprovalV1, SubagentPlanDecision, SubagentPlanV1, SubagentPolicySnapshot,
    SubagentTaskSpec,
};
mod resources;
mod sources;
mod types;
pub use codec::{SubagentDigest, SubagentRecord, SubagentRecordError};
pub use resources::SubagentResources;
pub use sources::{SubagentSourcePageV1, SubagentSourceSetV1};
pub use types::{BundledSubagentType, SubagentTypeSnapshotV1, bundled_subagent_types};
