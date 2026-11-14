#![forbid(unsafe_code)]
//! Source alerts are unconfirmed claims; host users never become Kubernetes principals.
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_domain::EvidenceHash;
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
macro_rules! table_module {
    ($name:ident, $id:literal, $file:literal, $digest:literal) => {
        pub struct $name(TableMapping);
        impl $name {
            pub fn new() -> Result<Self, MappingError> {
                let digest =
                    EvidenceHash::parse($digest).map_err(|_| MappingError::InvalidDefinition)?;
                TableMapping::bundled(include_str!($file), &digest).map(Self)
            }
        }
        impl SourceMapper for $name {
            fn manifest(&self) -> &MappingManifest {
                self.0.manifest()
            }
            fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
                self.0.map(source)
            }
        }
        impl Module for $name {
            fn manifest(&self) -> &'static ModuleManifest {
                const MODULE: ModuleManifest = ModuleManifest {
                    id: $id,
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
    };
}
table_module!(
    HostMapping,
    "mapping-falco-host",
    "host.toml",
    "000c426da8641a51750f3a7ebc18e2881d1d3c56c4062e6b9c9deddc62d5ed31"
);
table_module!(
    KubernetesMapping,
    "mapping-falco-kubernetes",
    "kubernetes.toml",
    "cc16f78e9c2ffe4ebf767ef58296d66a7d88ab27ec4472781a38aeb74b0701b7"
);
table_module!(
    AuditPluginMapping,
    "mapping-falco-kubernetes-audit",
    "kubernetes-audit.toml",
    "319dc7b4cbf1381a96470e0f3927b1e7503a8551e9fb3222a7d7cb510d8ef5ce"
);
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
