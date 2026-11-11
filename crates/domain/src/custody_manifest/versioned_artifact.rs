use super::{AuditEventKind, DomainError, EvidenceHash, ParquetArtifactV2, ParquetArtifactV3};

/// The supported case format contains only mapped V3 artifact envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParquetArtifact {
    V3(ParquetArtifactV3),
}
impl From<ParquetArtifactV3> for ParquetArtifact {
    fn from(value: ParquetArtifactV3) -> Self {
        Self::V3(value)
    }
}
impl ParquetArtifact {
    fn value(&self) -> &ParquetArtifactV3 {
        let Self::V3(value) = self;
        value
    }
    pub fn same_generation(&self, other: &Self) -> bool {
        self.value().same_mapping_generation(other.value())
    }
    pub fn decode(kind: AuditEventKind, payload: &str) -> Result<Self, DomainError> {
        match kind {
            AuditEventKind::ParquetArtifactV3 => ParquetArtifactV3::decode(payload).map(Self::V3),
            _ => Err(DomainError::InvalidManifest),
        }
    }
    pub const fn audit_kind(&self) -> AuditEventKind {
        match self {
            Self::V3(_) => AuditEventKind::ParquetArtifactV3,
        }
    }
    pub fn encode(&self) -> Result<String, DomainError> {
        self.value().encode()
    }
    pub fn validate(&self) -> Result<(), DomainError> {
        self.value().validate()
    }
    pub fn path(&self) -> &str {
        &self.value().core().path
    }
    pub fn size(&self) -> u64 {
        self.value().core().size
    }
    pub fn sha256(&self) -> &EvidenceHash {
        &self.value().core().sha256
    }
    pub fn parser_version(&self) -> &str {
        &self.value().core().parser_version
    }
    pub fn schema_version(&self) -> &str {
        self.value().core().schema.as_str()
    }
    pub fn partition_date(&self) -> &str {
        &self.value().core().partition.date
    }
    pub fn source_hashes(&self) -> &[EvidenceHash] {
        &self.value().core().source_hashes
    }
    /// Canonical grouping metadata is never an authorization scope.
    pub fn compaction_key(&self) -> Vec<u8> {
        let mut bytes = b"irmind-artifact-group-v1\0".to_vec();
        self.value().write_compaction_key(&mut bytes);
        bytes
    }
    /// The existing core encoding remains nested inside the V3 envelope.
    pub fn precise_metadata(&self) -> Option<&ParquetArtifactV2> {
        Some(self.value().core())
    }
    pub fn custody_identity(&self) -> Result<EvidenceHash, DomainError> {
        self.value().identity()
    }
}
