//! Pure mapping contracts and immutable per-ingestion selection.
mod bounded_reader;
pub use bounded_reader::BoundedSourceReader;
mod catalog;
mod decoder_selection;
pub mod framed;
mod installation;
pub mod json;
pub use installation::{ApprovedMappingDefinition, verify_mapping_installation};
mod normalization_budget;
pub mod ordered_decode;
mod ports;
pub use normalization_budget::{NormalizedExpansionProfile, NormalizedSourceBudget};
mod proofs;
pub(crate) use proofs::native_mapping_build_counts;
pub use proofs::{mapping_installation_proofs, required_mapping_installations};
mod prepared;
mod stream;
mod time;

pub use catalog::MappingCatalog;
pub use decoder_selection::SourceDecoderSelection;
pub use irmind_mapping_contracts::source_mapping::*;
pub use ports::{
    DecodeBudget, DecodeInput, SourceDecoder, SourceFileInput, SourceInput, SourceMetadata,
};
pub use prepared::{BoundMappingSource, MappedArtifactProjection, PreparedMappingSource};

pub use stream::{
    DecodedSourceCommitmentV1, MappedSourceRecord, PreparedSourceRecord, SourceRecordAccumulator,
    SourceRecordPreparer, SourceRecordReplay,
};

pub use time::{decode_source_time_context, parser_time_context, source_time_snapshot};

impl From<MappingError> for crate::AppError {
    fn from(error: MappingError) -> Self {
        Self::Policy(error.to_string())
    }
}
