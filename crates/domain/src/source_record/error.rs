#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRecordError {
    Limit,
    InvalidNumber,
    InvalidPath,
    InvalidDescriptor,
    InvalidOrigin,
    DuplicateField,
    InvalidEncoding,
}

impl std::fmt::Display for SourceRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Limit => "source record exceeds its contract limits",
            Self::InvalidNumber => "invalid exact source number",
            Self::InvalidPath => "invalid segmented source path",
            Self::InvalidDescriptor => "invalid source format descriptor",
            Self::InvalidOrigin => "invalid source record provenance",
            Self::DuplicateField => "duplicate source field",
            Self::InvalidEncoding => "invalid bounded source encoding",
        })
    }
}
impl std::error::Error for SourceRecordError {}
