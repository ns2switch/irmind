/// Provenance of an audit event. The wire names are part of the signed format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditOrigin {
    Agent,
    Analyst,
    Guard,
    Model,
    Policy,
    System,
}

impl AuditOrigin {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Analyst => "analyst",
            Self::Guard => "guard",
            Self::Model => "model",
            Self::Policy => "policy",
            Self::System => "system",
        }
    }
}
