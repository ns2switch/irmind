use super::SourceRecordError;
use crate::{EvidenceHash, SourceKind};

/// Describes acquisition, not authority to open a path or contact a service.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceReferenceV1 {
    reference: String,
    kind: SourceKind,
    acquisition: Option<EvidenceHash>,
}
impl SourceReferenceV1 {
    pub fn try_new(
        reference: &str,
        kind: SourceKind,
        acquisition: Option<EvidenceHash>,
    ) -> Result<Self, SourceRecordError> {
        if !crate::custody_manifest::valid_source(reference)
            || !matches!(kind, SourceKind::File | SourceKind::ToolResult)
        {
            return Err(SourceRecordError::InvalidOrigin);
        }
        Ok(Self {
            reference: reference.into(),
            kind,
            acquisition,
        })
    }
    pub fn file(reference: &str) -> Result<Self, SourceRecordError> {
        Self::try_new(reference, SourceKind::File, None)
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub const fn kind(&self) -> SourceKind {
        self.kind
    }
    pub const fn acquisition(&self) -> Option<&EvidenceHash> {
        self.acquisition.as_ref()
    }
    pub(super) const fn kind_code(&self) -> u8 {
        match self.kind {
            SourceKind::ToolResult => 1,
            _ => 0,
        }
    }
}
