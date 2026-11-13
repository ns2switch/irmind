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
    "5f8cebeb48c38c7fda2703bf03a152281494624e35b201c85b7ce43f99fc37c3"
);
table_module!(
    KubernetesMapping,
    "mapping-falco-kubernetes",
    "kubernetes.toml",
    "69ad17a3c84d93ff9e9fcd94f7acd4b063725b1e225a07f3ca9cf4ddf64ad1fb"
);
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
