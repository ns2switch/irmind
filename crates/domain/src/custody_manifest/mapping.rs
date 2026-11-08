//! Explicit source/pipeline custody. Historical envelope and seal codecs are unchanged.
mod artifact;
mod binding;
mod commitments;
mod contracts;
pub use contracts::{common_event_contract_digest, source_record_contract_digest};
mod layout;
mod lineage;
pub use layout::ParquetLayoutV1;
pub use lineage::MappingLineageV1;
mod profile;
mod run;
pub use artifact::{
    ArtifactDerivationV1, ArtifactParentV1, ArtifactPipelineV1, PARQUET_LAYOUT_BUILDER_V1,
    ParquetArtifactV3,
};
pub use binding::MappingBindingV1;
pub use run::{MappingCountsV1, MappingRouteV1, MappingRunV1};
mod source_set;
mod wire;
pub use profile::{
    MAPPING_SELECTION_V1, MappingInputRefV1, MappingProfileRecordV1, MappingProfileV1,
    MappingSnapshotRefV1, MappingSnapshotV1,
};
pub use source_set::{SourceDecoderIdentityV1, SourceFormatIdentityV1, SourceRecordSetV1};

use crate::{DomainError, EvidenceHash};
use sha2::{Digest, Sha256};

pub(super) fn invalid() -> DomainError {
    DomainError::InvalidManifest
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

pub(super) fn hash_payload(payload: &str, tag: &[u8]) -> Result<EvidenceHash, DomainError> {
    let bytes = wire::decode(payload, tag, wire::MAX_METADATA)?;
    Ok(EvidenceHash::from_bytes(Sha256::digest(bytes).into()))
}
