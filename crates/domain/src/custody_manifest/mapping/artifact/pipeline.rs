use super::{DomainError, EvidenceHash, MappingBindingV1, PARQUET_LAYOUT_BUILDER_V1, invalid};
use crate::custody_manifest::valid_relative_path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactParentV1 {
    path: String,
    identity: EvidenceHash,
}
impl ArtifactParentV1 {
    pub fn try_new(path: String, identity: EvidenceHash) -> Result<Self, DomainError> {
        if path.len() > 1024 || !valid_relative_path(&path) || !path.ends_with(".parquet") {
            return Err(invalid());
        }
        Ok(Self { path, identity })
    }
    pub fn from_artifact(value: &super::ParquetArtifactV3) -> Result<Self, DomainError> {
        Self::try_new(value.core().path.clone(), value.identity()?)
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub const fn identity(&self) -> &EvidenceHash {
        &self.identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactDerivationV1 {
    Mapped,
    Layout { parents: Vec<ArtifactParentV1> },
}

/// Both derivations retain the original per-source interpretation bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactPipelineV1 {
    bindings: Vec<MappingBindingV1>,
    rows: u64,
    derivation: ArtifactDerivationV1,
}
impl ArtifactPipelineV1 {
    pub fn mapped(bindings: Vec<MappingBindingV1>, rows: u64) -> Result<Self, DomainError> {
        let first = bindings.first().ok_or_else(invalid)?;
        if bindings
            .iter()
            .any(|b| b.profile() != first.profile() || b.catalog() != first.catalog())
        {
            return Err(invalid());
        }
        Self::checked(bindings, rows, ArtifactDerivationV1::Mapped)
    }
    pub fn layout(
        bindings: Vec<MappingBindingV1>,
        rows: u64,
        parents: Vec<ArtifactParentV1>,
    ) -> Result<Self, DomainError> {
        if parents.len() < 2
            || parents.len() > 128
            || !parents.windows(2).all(|p| p[0].path < p[1].path)
            || parents
                .iter()
                .map(|p| &p.identity)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != parents.len()
        {
            return Err(invalid());
        }
        Self::checked(bindings, rows, ArtifactDerivationV1::Layout { parents })
    }
    fn checked(
        bindings: Vec<MappingBindingV1>,
        rows: u64,
        derivation: ArtifactDerivationV1,
    ) -> Result<Self, DomainError> {
        let inputs = super::super::binding::validate_bindings(&bindings)?;
        if rows == 0 || rows > inputs.checked_mul(160).ok_or_else(invalid)? {
            return Err(invalid());
        }
        Ok(Self {
            bindings,
            rows,
            derivation,
        })
    }
    pub fn bindings(&self) -> &[MappingBindingV1] {
        &self.bindings
    }
    pub const fn rows(&self) -> u64 {
        self.rows
    }
    pub const fn derivation(&self) -> &ArtifactDerivationV1 {
        &self.derivation
    }
    pub fn accepts_builder(&self, builder: &str) -> bool {
        match self.derivation {
            ArtifactDerivationV1::Mapped => matches!(
                builder,
                crate::COMMON_EVENT_BUILDER | crate::COMMON_EVENT_DIRECT_BUILDER
            ),
            ArtifactDerivationV1::Layout { .. } => builder == PARQUET_LAYOUT_BUILDER_V1,
        }
    }
    pub fn builder(&self) -> &'static str {
        match self.derivation {
            ArtifactDerivationV1::Mapped => crate::COMMON_EVENT_BUILDER,
            ArtifactDerivationV1::Layout { .. } => PARQUET_LAYOUT_BUILDER_V1,
        }
    }
}
