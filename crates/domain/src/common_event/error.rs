#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventSchemaError {
    UnknownCode,
    InvalidValue,
    InvalidFieldType,
    DuplicateField,
    InvalidObservation,
    InvalidOrigin,
    LimitExceeded,
}
impl std::fmt::Display for EventSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnknownCode => "unknown common event code",
            Self::InvalidValue => "invalid common event value",
            Self::InvalidFieldType => "common event field has an incompatible type",
            Self::DuplicateField => "common event field is duplicated",
            Self::InvalidObservation => "inconsistent common entity observation",
            Self::InvalidOrigin => "invalid common event origin",
            Self::LimitExceeded => "common event exceeds a schema limit",
        })
    }
}
impl std::error::Error for EventSchemaError {}
