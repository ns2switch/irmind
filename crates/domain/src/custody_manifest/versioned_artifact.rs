use super::{AuditEventKind, DomainError, EvidenceHash, ParquetArtifactV1, ParquetArtifactV2};

/// Explicit wire-version dispatch; a V2 artifact is never disguised as V1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParquetArtifact {
    V1(ParquetArtifactV1),
    V2(ParquetArtifactV2),
}

impl From<ParquetArtifactV1> for ParquetArtifact {
    fn from(value: ParquetArtifactV1) -> Self {
        Self::V1(value)
    }
}

impl From<ParquetArtifactV2> for ParquetArtifact {
    fn from(value: ParquetArtifactV2) -> Self {
        Self::V2(value)
    }
}

impl ParquetArtifact {
    pub fn decode(kind: AuditEventKind, payload: &str) -> Result<Self, DomainError> {
        match kind {
            AuditEventKind::ParquetArtifactV1 => ParquetArtifactV1::decode(payload).map(Self::V1),
            AuditEventKind::ParquetArtifactV2 => ParquetArtifactV2::decode(payload).map(Self::V2),
            _ => Err(DomainError::InvalidManifest),
        }
    }
    pub const fn audit_kind(&self) -> AuditEventKind {
        match self {
            Self::V1(_) => AuditEventKind::ParquetArtifactV1,
            Self::V2(_) => AuditEventKind::ParquetArtifactV2,
        }
    }
    pub fn encode(&self) -> Result<String, DomainError> {
        match self {
            Self::V1(v) => v.encode(),
            Self::V2(v) => v.encode(),
        }
    }
    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::V1(v) => v.validate(),
            Self::V2(v) => v.validate(),
        }
    }
    pub fn path(&self) -> &str {
        match self {
            Self::V1(v) => &v.path,
            Self::V2(v) => &v.path,
        }
    }
    pub const fn size(&self) -> u64 {
        match self {
            Self::V1(v) => v.size,
            Self::V2(v) => v.size,
        }
    }
    pub fn sha256(&self) -> &EvidenceHash {
        match self {
            Self::V1(v) => &v.sha256,
            Self::V2(v) => &v.sha256,
        }
    }
    pub fn parser_version(&self) -> &str {
        match self {
            Self::V1(v) => &v.parser_version,
            Self::V2(v) => &v.parser_version,
        }
    }
    pub fn schema_version(&self) -> &str {
        match self {
            Self::V1(v) => &v.schema_version,
            Self::V2(v) => v.schema.as_str(),
        }
    }
    pub fn partition_date(&self) -> &str {
        match self {
            Self::V1(v) => &v.partition_date,
            Self::V2(v) => &v.partition.date,
        }
    }
    pub fn source_hashes(&self) -> &[EvidenceHash] {
        match self {
            Self::V1(v) => &v.source_hashes,
            Self::V2(v) => &v.source_hashes,
        }
    }
    /// Canonical grouping metadata only; never used as an authorization scope.
    pub fn compaction_key(&self) -> Vec<u8> {
        let mut bytes = b"irmind-artifact-group-v1\0".to_vec();
        match self {
            Self::V1(v) => {
                bytes.push(1);
                for value in [
                    v.partition_date.as_str(),
                    &v.partition_account,
                    &v.partition_region,
                    &v.schema_version,
                    v.parser_version
                        .strip_suffix("+compact-v1")
                        .unwrap_or(&v.parser_version),
                ] {
                    super::put(&mut bytes, value.as_bytes());
                }
            }
            Self::V2(v) => {
                bytes.push(2);
                v.partition.write(&mut bytes);
                for value in [
                    v.schema.as_str(),
                    &v.parser_id,
                    &v.parser_version,
                    &v.time_semantics,
                    &v.stable_order,
                    &v.builder_version,
                ] {
                    super::put(&mut bytes, value.as_bytes());
                }
            }
        }
        bytes
    }

    pub fn partition_account(&self) -> &str {
        self.legacy_partition(true)
    }
    pub fn partition_region(&self) -> &str {
        self.legacy_partition(false)
    }
    fn legacy_partition(&self, account: bool) -> &str {
        match self {
            Self::V1(v) => {
                if account {
                    &v.partition_account
                } else {
                    &v.partition_region
                }
            }
            Self::V2(_) => "",
        }
    }
    pub fn v1(&self) -> Result<&ParquetArtifactV1, DomainError> {
        match self {
            Self::V1(v) => Ok(v),
            Self::V2(_) => Err(DomainError::InvalidManifest),
        }
    }
}
