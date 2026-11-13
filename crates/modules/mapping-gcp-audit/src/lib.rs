#![forbid(unsafe_code)]
//! Audit status/service tables; GKE additionally validates hierarchical resource paths.
mod gke;
pub use gke::GkeMapping;
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_domain::EvidenceHash;
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
const CLOUD: &str = include_str!("cloud.toml");
const CLOUD_DIGEST: &str = "9bbdd74600a9b03315e3743dc6c173cadc379f663914dbc1adcbf36ec7ad69d2";
pub struct CloudAuditMapping(TableMapping);
impl CloudAuditMapping {
    pub fn new() -> Result<Self, MappingError> {
        TableMapping::bundled(
            CLOUD,
            &EvidenceHash::parse(CLOUD_DIGEST).map_err(|_| MappingError::InvalidDefinition)?,
        )
        .map(Self)
    }
}
impl SourceMapper for CloudAuditMapping {
    fn manifest(&self) -> &MappingManifest {
        self.0.manifest()
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.0.map(source)
    }
}
static CLOUD_MODULE: ModuleManifest = module("mapping-gcp-audit");
static GKE_MODULE: ModuleManifest = module("mapping-gke-audit");
const fn module(id: &'static str) -> ModuleManifest {
    ModuleManifest {
        id,
        version: "0.1.0",
        ports: &[ModulePort::SourceMapper],
        tools: &[],
        config: &[],
    }
}
impl Module for CloudAuditMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        &CLOUD_MODULE
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), irmind_app::AppError> {
        registry.add_source_mapper(Arc::new(*self))
    }
}
impl Module for GkeMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        &GKE_MODULE
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), irmind_app::AppError> {
        registry.add_source_mapper(Arc::new(*self))
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
