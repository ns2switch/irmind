//! Pure, bounded contracts for source mappings.
mod error;
pub mod json;
mod manifest;
mod output;
mod selector;
mod snapshot;

pub use error::MappingError;
pub use manifest::{MappingManifest, MappingProvenance};
pub use output::{MappingDiagnostic, MappingOutput, MappingPartition};
pub use selector::{SelectorCondition, SelectorPredicate, SelectorScalar, SourceSelector};

pub use irmind_domain::{
    DecodeAnnotationsV1, MappingIdentityV1, SourceDiscriminator, SourceFormatV1, SourceNumber,
    SourcePath, SourcePathSegment, SourceRecordError, SourceRecordV1, SourceReferenceV1,
    SourceValue,
};

/// A bounded pure function. Modules receive no I/O, secret, clock or tool ports.
pub trait SourceMapper: Send + Sync {
    fn manifest(&self) -> &MappingManifest;
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError>;
}
