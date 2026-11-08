//! Pure mapping contracts and immutable per-ingestion selection.
mod catalog;
mod decoder_selection;
mod error;
mod installation;
pub mod json;
mod manifest;
pub use installation::{ApprovedMappingDefinition, verify_mapping_installation};
mod output;
mod ports;
mod proofs;
pub use proofs::{mapping_installation_proofs, required_mapping_installations};
mod prepared;
mod selector;
mod snapshot;
mod stream;
mod time;

pub use catalog::MappingCatalog;
pub use decoder_selection::SourceDecoderSelection;
pub use error::MappingError;
pub use irmind_domain::{
    DecodeAnnotationsV1, MappingIdentityV1, SourceDiscriminator, SourceFormatV1, SourceNumber,
    SourcePath, SourcePathSegment, SourceRecordError, SourceRecordV1, SourceReferenceV1,
    SourceValue,
};
pub use manifest::{MappingManifest, MappingProvenance};
pub use output::{MappingDiagnostic, MappingOutput, MappingPartition};
pub use ports::{SourceDecoder, SourceFileInput, SourceInput, SourceMapper, SourceMetadata};
pub use prepared::{BoundMappingSource, MappedArtifactProjection, PreparedMappingSource};
pub use selector::{SelectorCondition, SelectorPredicate, SelectorScalar, SourceSelector};

pub use stream::{DecodedSourceCommitmentV1, MappedSourceRecord, SourceRecordAccumulator};

pub use time::{decode_source_time_context, parser_time_context, source_time_snapshot};
