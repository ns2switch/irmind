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
pub struct KubernetesMapping {
    table: TableMapping,
    module: &'static ModuleManifest,
}
impl KubernetesMapping {
    pub fn new() -> Result<Self, MappingError> {
        Self::included(DEFINITION, DIGEST, &MODULE)
    }
    pub fn all() -> Result<Vec<Self>, MappingError> {
        Ok(vec![
            Self::new()?,
            Self::included(
                include_str!("eks.toml"),
                "a364062e21ecfae08e1749c7392115517a28708460b43a3d1feaaa3340a0fa5e",
                &EKS_MODULE,
            )?,
            Self::included(
                include_str!("aks.toml"),
                "9fa114c12f152ae73a19f390f0f1cb833c22e1e62f59b47f50ccd339278d907f",
                &AKS_MODULE,
            )?,
        ])
    }
    fn included(
        text: &str,
        digest: &str,
        module: &'static ModuleManifest,
    ) -> Result<Self, MappingError> {
        let digest = EvidenceHash::parse(digest).map_err(|_| MappingError::InvalidDefinition)?;
        Ok(Self {
            table: TableMapping::bundled(text, &digest)?,
            module,
        })
    }
}
impl SourceMapper for KubernetesMapping {
    fn manifest(&self) -> &MappingManifest {
        self.table.manifest()
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.table.map(source)
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
        self.module
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), irmind_app::AppError> {
        registry.add_source_mapper(Arc::new(*self))
    }
}
static EKS_MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-eks-audit",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
static AKS_MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-aks-audit",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod managed_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
