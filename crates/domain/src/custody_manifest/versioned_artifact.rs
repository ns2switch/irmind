use super::{
    AuditEventKind, DomainError, EvidenceHash, ParquetArtifactV1, ParquetArtifactV2,
    ParquetArtifactV3,
};

/// Explicit wire-version dispatch; a V2 artifact is never disguised as V1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParquetArtifact {
    V1(ParquetArtifactV1),
    V2(ParquetArtifactV2),
    V3(ParquetArtifactV3),
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

impl From<ParquetArtifactV3> for ParquetArtifact {
    fn from(value: ParquetArtifactV3) -> Self {
        Self::V3(value)
    }
}

impl ParquetArtifact {
    /// A source can acquire a new derived generation only through migration.
    pub fn same_generation(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V1(a), Self::V1(b)) => {
                a.parser_version
                    .strip_suffix("+compact-v1")
                    .unwrap_or(&a.parser_version)
                    == b.parser_version
                        .strip_suffix("+compact-v1")
                        .unwrap_or(&b.parser_version)
            }
            (Self::V2(a), Self::V2(b)) => {
                a.parser_id == b.parser_id
                    && a.parser_version == b.parser_version
                    && a.builder_version == b.builder_version
                    && a.time_semantics == b.time_semantics
                    && a.stable_order == b.stable_order
                    && a.partition.key_set == b.partition.key_set
                    && a.partition.policy == b.partition.policy
            }
            (Self::V3(a), Self::V3(b)) => a.same_mapping_generation(b),
            _ => false,
        }
    }

    pub fn decode(kind: AuditEventKind, payload: &str) -> Result<Self, DomainError> {
        match kind {
            AuditEventKind::ParquetArtifactV1 => ParquetArtifactV1::decode(payload).map(Self::V1),
            AuditEventKind::ParquetArtifactV2 => ParquetArtifactV2::decode(payload).map(Self::V2),
            AuditEventKind::ParquetArtifactV3 => ParquetArtifactV3::decode(payload).map(Self::V3),
            _ => Err(DomainError::InvalidManifest),
        }
    }
    pub const fn audit_kind(&self) -> AuditEventKind {
        match self {
            Self::V1(_) => AuditEventKind::ParquetArtifactV1,
            Self::V2(_) => AuditEventKind::ParquetArtifactV2,
            Self::V3(_) => AuditEventKind::ParquetArtifactV3,
        }
    }
    pub fn encode(&self) -> Result<String, DomainError> {
        match self {
            Self::V1(v) => v.encode(),
            Self::V2(v) => v.encode(),
            Self::V3(v) => v.encode(),
        }
    }
    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::V1(v) => v.validate(),
            Self::V2(v) => v.validate(),
            Self::V3(v) => v.validate(),
        }
    }
    pub fn path(&self) -> &str {
        match self {
            Self::V1(v) => &v.path,
            Self::V2(v) => &v.path,
            Self::V3(v) => &v.core().path,
        }
    }
    pub const fn size(&self) -> u64 {
        match self {
            Self::V1(v) => v.size,
            Self::V2(v) => v.size,
            Self::V3(v) => v.core().size,
        }
    }
    pub fn sha256(&self) -> &EvidenceHash {
        match self {
            Self::V1(v) => &v.sha256,
            Self::V2(v) => &v.sha256,
            Self::V3(v) => &v.core().sha256,
        }
    }
    pub fn parser_version(&self) -> &str {
        match self {
            Self::V1(v) => &v.parser_version,
            Self::V2(v) => &v.parser_version,
            Self::V3(v) => &v.core().parser_version,
        }
    }
    pub fn schema_version(&self) -> &str {
        match self {
            Self::V1(v) => &v.schema_version,
            Self::V2(v) => v.schema.as_str(),
            Self::V3(v) => v.core().schema.as_str(),
        }
    }
    pub fn partition_date(&self) -> &str {
        match self {
            Self::V1(v) => &v.partition_date,
            Self::V2(v) => &v.partition.date,
            Self::V3(v) => &v.core().partition.date,
        }
    }
    pub fn source_hashes(&self) -> &[EvidenceHash] {
        match self {
            Self::V1(v) => &v.source_hashes,
            Self::V2(v) => &v.source_hashes,
            Self::V3(v) => &v.core().source_hashes,
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
            Self::V3(v) => v.write_compaction_key(&mut bytes),
        }
        bytes
    }

    /// Precise physical metadata only; never an envelope-version conversion.
    pub const fn precise_metadata(&self) -> Option<&ParquetArtifactV2> {
        match self {
            Self::V1(_) => None,
            Self::V2(v) => Some(v),
            Self::V3(v) => Some(v.core()),
        }
    }
    /// Historical identities are file hashes; V3 identifies the complete derivation.
    pub fn custody_identity(&self) -> Result<EvidenceHash, DomainError> {
        match self {
            Self::V3(v) => v.identity(),
            Self::V1(_) | Self::V2(_) => Ok(self.sha256().clone()),
        }
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
            Self::V2(_) | Self::V3(_) => "",
        }
    }
    pub fn v1(&self) -> Result<&ParquetArtifactV1, DomainError> {
        match self {
            Self::V1(v) => Ok(v),
            Self::V2(_) | Self::V3(_) => Err(DomainError::InvalidManifest),
        }
    }
}
