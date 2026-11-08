#![forbid(unsafe_code)]
//! Bounded declarative mappings. The interpreter receives no I/O or clock ports.
mod compile;
mod definition;
mod fields;
mod map;
use irmind_app::source_mapping::{
    MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1, SourceSelector,
};
use irmind_domain::EventHeaderV1;

pub struct TableMapping {
    manifest: MappingManifest,
    rules: Vec<CompiledRule>,
    fields: Vec<fields::CompiledField>,
    partition: fields::CompiledPartition,
    action: Option<irmind_app::source_mapping::SourcePath>,
}
struct CompiledRule {
    selector: SourceSelector,
    header: EventHeaderV1,
    fields: Vec<fields::CompiledField>,
}
impl SourceMapper for TableMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.project(source)
    }
}
impl std::fmt::Debug for TableMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TableMapping")
            .field("identity", self.manifest.identity())
            .finish_non_exhaustive()
    }
}
fn invalid<T>(_: T) -> MappingError {
    MappingError::InvalidDefinition
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
