mod mailbox;
use super::PortFuture;
use super::{SubagentDigest, SubagentPlanV1, SubagentRecord, SubagentResources, SubagentTaskSpec};
use crate::{AppError, CancellationToken};
pub use mailbox::{AnalystPlanMailbox, PlanReview};

/// Immutable guarded preview. Its bindings are returned by the trusted UI.
/// There is no deserializer and no model-facing confirmation field.
#[derive(Clone)]
pub struct SafePlanPreview {
    pub(super) plan: SubagentPlanV1,
    pub(super) confirmation_required: bool,
}
impl SafePlanPreview {
    pub fn case_id(&self) -> &str {
        &self.plan.case_id
    }
    pub fn plan_id(&self) -> SubagentDigest {
        self.plan.plan_id
    }
    pub fn tasks(&self) -> &[SubagentTaskSpec] {
        &self.plan.tasks
    }
    pub const fn reservation(&self) -> SubagentResources {
        self.plan.reservation
    }
    pub const fn remaining(&self) -> SubagentResources {
        self.plan.remaining
    }
    pub const fn confirmation_required(&self) -> bool {
        self.confirmation_required
    }
    pub fn start(&self) -> Result<AnalystPlanChoice, AppError> {
        self.choice(true, true)
    }
    pub fn cancel(&self) -> Result<AnalystPlanChoice, AppError> {
        self.choice(false, true)
    }
    pub fn automatic_start(&self) -> Result<AnalystPlanChoice, AppError> {
        if self.confirmation_required {
            return Err(super::queries::unsupported());
        }
        self.choice(true, false)
    }
    fn choice(&self, start: bool, explicit: bool) -> Result<AnalystPlanChoice, AppError> {
        Ok(AnalystPlanChoice {
            plan: self
                .plan
                .identity()
                .map_err(|_| super::queries::unsupported())?,
            budget: self.plan.budget_checkpoint_sha256,
            start,
            explicit,
        })
    }
}
pub struct AnalystPlanChoice {
    pub(super) plan: SubagentDigest,
    pub(super) budget: SubagentDigest,
    pub(super) start: bool,
    pub(super) explicit: bool,
}
impl AnalystPlanChoice {
    pub const fn starts(&self) -> bool {
        self.start
    }
    pub const fn explicit(&self) -> bool {
        self.explicit
    }
    pub const fn plan(&self) -> SubagentDigest {
        self.plan
    }
    pub const fn budget(&self) -> SubagentDigest {
        self.budget
    }
}
pub trait AnalystPlanInteraction: Send + Sync {
    fn review<'a>(
        &'a self,
        preview: &'a SafePlanPreview,
        cancel: &'a CancellationToken,
    ) -> PortFuture<'a, AnalystPlanChoice>;
}
