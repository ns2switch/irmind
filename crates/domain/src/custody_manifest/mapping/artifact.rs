mod codec;
mod pipeline;
use super::{DomainError, EvidenceHash, MappingBindingV1, hash_payload, invalid};
use crate::ParquetArtifactV2;
pub use pipeline::{ArtifactDerivationV1, ArtifactParentV1, ArtifactPipelineV1};

pub(super) const TAG: &[u8] = b"irmind-parquet-artifact-v3\0";
pub const PARQUET_LAYOUT_BUILDER_V1: &str = "parquet-layout-common-event-v1";

/// A separate derivation envelope; historical V2 encoding is never extended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParquetArtifactV3 {
    core: ParquetArtifactV2,
    pipeline: ArtifactPipelineV1,
}
impl ParquetArtifactV3 {
    pub fn try_new(
        core: ParquetArtifactV2,
        pipeline: ArtifactPipelineV1,
    ) -> Result<Self, DomainError> {
        core.validate()?;
        let inputs = super::binding::validate_bindings(pipeline.bindings())?;
        let decoder = pipeline.bindings().first().ok_or_else(invalid)?.decoder();
        if !core.schema.is_common()
            || core.builder_version != pipeline.builder()
            || core.parser_id != decoder.id()
            || core.parser_version != decoder.version()
            || !core.superseded_hashes.is_empty()
            || core.source_hashes
                != pipeline
                    .bindings()
                    .iter()
                    .map(|b| b.input().source().clone())
                    .collect::<Vec<_>>()
            || (core.schema == crate::ArtifactSchemaV2::CommonEvents && pipeline.rows() > inputs)
        {
            return Err(invalid());
        }
        let value = Self { core, pipeline };
        value.encode()?;
        Ok(value)
    }
    pub const fn core(&self) -> &ParquetArtifactV2 {
        &self.core
    }
    pub const fn pipeline(&self) -> &ArtifactPipelineV1 {
        &self.pipeline
    }
    /// Canonical envelope identity differs from its physical file SHA-256.
    pub fn identity(&self) -> Result<EvidenceHash, DomainError> {
        hash_payload(&self.encode()?, TAG)
    }
    pub fn bindings(&self) -> &[MappingBindingV1] {
        self.pipeline.bindings()
    }
}
