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
const DIGEST: &str = "832d119ca0d776a13a10ff56c814e98eecd575a5eee5eb25d3d492079d7bd63f";
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
                "6946c0c91035030f453ea9a5614c3f199f2324f7440c4753c61130d3fa431b40",
                &EKS_MODULE,
            )?,
            Self::included(
                include_str!("aks.toml"),
                "67b131b48babbdec174758e46349e492cf3a71df8abd38e92df20268518e77f5",
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
