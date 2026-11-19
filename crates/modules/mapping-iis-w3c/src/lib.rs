#![forbid(unsafe_code)]
//! Finite IIS W3C HTTP field and outcome rules.
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;

pub struct IisW3cMapping(TableMapping);

impl IisW3cMapping {
    pub fn new() -> Result<Self, MappingError> {
        let definition = include_str!("events.toml");
        let reviewed = TableMapping::review(definition)?;
        TableMapping::bundled(definition, reviewed.identity().implementation()).map(Self)
    }
}

impl Module for IisW3cMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        static MODULE: ModuleManifest = ModuleManifest {
            id: "mapping-iis-w3c",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        };
        &MODULE
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), irmind_app::AppError> {
        registry.add_source_mapper(Arc::new(*self))
    }
}

impl SourceMapper for IisW3cMapping {
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
