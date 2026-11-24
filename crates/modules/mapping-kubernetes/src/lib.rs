#![forbid(unsafe_code)]
//! Finite Kubernetes audit interpretation; source context never grants permissions.
use irmind_domain::EvidenceHash;
use irmind_mapping_contracts::common_event::cluster_audit::{self, AuditExactField};
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_mapping_tables::TableMapping;
const DEFINITION: &str = include_str!("kubernetes.toml");
const DIGEST: &str = "28a09caaed2973d2276939a71540ad4e6d9182dc3ccee2b67194b778da51fac7";
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
                "c7a2ab7a418cede5a586c0607761de98c453795927be2c085b5a28861b1750a2",
                &EKS_MODULE,
            )?,
            Self::included(
                include_str!("aks.toml"),
                "59d339d022033157ac00d4c43ccc26bf2742aa5e7ac87c3d7ec9b7f3dbb302a3",
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
        let output = self.table.project_cluster_audit(source)?;
        let partition = output.partition().clone();
        let mut record = output.into_record();
        let field = if self.module.id == MODULE.id {
            AuditExactField::SourceIps
        } else {
            AuditExactField::WrappedSourceIps
        };
        record.indexed.record.text = cluster_audit::encode(&record.common, source.fields(), field)
            .map_err(|_| MappingError::InvalidOutput)?;
        MappingOutput::try_new(source, record.indexed, record.common, partition, vec![])
    }
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-kubernetes",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl MappingModule for KubernetesMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        self.module
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
