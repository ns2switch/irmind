#![forbid(unsafe_code)]
//! Finite Kubernetes audit interpretation; source context never grants permissions.
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_domain::EvidenceHash;
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
const DEFINITION: &str = include_str!("kubernetes.toml");
const DIGEST: &str = "87c111421e7ba27f4581236c08d2bdddc6f723041f9a447039f7e8a85cdc4f7c";
pub struct KubernetesMapping(TableMapping);
impl KubernetesMapping {
    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::parse(DIGEST).map_err(|_| MappingError::InvalidDefinition)?;
        TableMapping::bundled(DEFINITION, &digest).map(Self)
    }
}
impl SourceMapper for KubernetesMapping {
    fn manifest(&self) -> &MappingManifest {
        self.0.manifest()
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.0.map(source)
    }
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-kubernetes",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl Module for KubernetesMapping {
    fn manifest(&self) -> &'static ModuleManifest {
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
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
