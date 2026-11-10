#![forbid(unsafe_code)]
//! Bundled Windows tables; EVTX decoding never assigns classification or roles.
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
                const MANIFEST: ModuleManifest = ModuleManifest {
                    id: $id,
                    version: "0.1.0",
                    ports: &[ModulePort::SourceMapper],
                    tools: &[],
                    config: &[],
                };
                &MANIFEST
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
mod security;
pub use security::SecurityMapping;
table_module!(
    SystemMapping,
    "mapping-evtx-system",
    "tables/system.toml",
    "46417598368150df1cacefcf813267a6706f57b9e269f833f5b74401ff2d194c"
);
table_module!(
    PowerShellMapping,
    "mapping-evtx-powershell",
    "tables/powershell.toml",
    "eca590ff59394e3097a889f3e73d341509c0c1868c045a08e3d95b77aff2728c"
);
table_module!(
    SysmonMapping,
    "mapping-evtx-sysmon",
    "tables/sysmon.toml",
    "4e3343194df2024e608a085dd4bad682f7ba408ac66b1ee2825ca47d9f835d05"
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
