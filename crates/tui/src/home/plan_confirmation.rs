#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PlanConfirmation {
    ThresholdOnly,
    AllPlans,
}
impl PlanConfirmation {
    pub(super) fn all(self) -> bool {
        self == Self::AllPlans
    }
}
impl From<bool> for PlanConfirmation {
    fn from(all: bool) -> Self {
        if all {
            Self::AllPlans
        } else {
            Self::ThresholdOnly
        }
    }
}
