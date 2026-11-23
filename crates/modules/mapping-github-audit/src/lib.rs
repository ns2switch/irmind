#![forbid(unsafe_code)]
//! Finite GitHub audit operation rules. Original token metadata stays in evidence.
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_mapping_tables::TableMapping;

pub struct GitHubAuditMapping(TableMapping);

impl GitHubAuditMapping {
    pub fn new() -> Result<Self, MappingError> {
        let definition = include_str!("events.toml");
        let reviewed = TableMapping::review(definition)?;
        TableMapping::bundled(definition, reviewed.identity().implementation()).map(Self)
    }
}

impl MappingModule for GitHubAuditMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        static MODULE: ModuleManifest = ModuleManifest {
            id: "mapping-github-audit",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        };
        &MODULE
    }
}

impl SourceMapper for GitHubAuditMapping {
    fn manifest(&self) -> &MappingManifest {
        self.0.manifest()
    }

    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.0.map(source)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
