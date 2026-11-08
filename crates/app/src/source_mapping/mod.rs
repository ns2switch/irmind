//! Pure mapping contracts and immutable per-ingestion selection.
mod catalog;
mod decoder_selection;
mod error;
pub mod json;
mod manifest;
mod output;
mod ports;
mod selector;

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
pub use selector::{SelectorCondition, SelectorPredicate, SelectorScalar, SourceSelector};
