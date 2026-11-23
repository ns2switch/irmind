#![forbid(unsafe_code)]
//! Finite AWS ELB HTTP field and outcome rules.
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_mapping_tables::TableMapping;

pub struct ElbMapping(TableMapping);

impl ElbMapping {
    pub fn new() -> Result<Self, MappingError> {
        let definition = include_str!("events.toml");
        let reviewed = TableMapping::review(definition)?;
        TableMapping::bundled(definition, reviewed.identity().implementation()).map(Self)
    }
}

impl MappingModule for ElbMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        static MODULE: ModuleManifest = ModuleManifest {
            id: "mapping-elb",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        };
        &MODULE
    }
}

impl SourceMapper for ElbMapping {
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
