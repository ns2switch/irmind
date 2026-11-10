#![forbid(unsafe_code)]
//! Linux mappings are separate modules; only decoding belongs to parser-linux.
mod audit;
mod auth_extraction;
pub use audit::AuditMapping;
pub use auth_extraction::AuthExtractionMapping;
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
table_module!(
    SshdMapping,
    "mapping-linux-sshd",
    "sshd.toml",
    "e351efe72e18a0a3d8bd1e1e5bae3ecedf33c37e94303f8e3295ecf80b2a910a"
);
table_module!(
    SudoMapping,
    "mapping-linux-sudo",
    "sudo.toml",
    "1fbe4bd1ea07a66bb6229b2ffad0fea42fa5d500a41240ff9d32c21afd0ac392"
);
table_module!(
    SuMapping,
    "mapping-linux-su",
    "su.toml",
    "cfb60061af2a0051eda792c14de035bb477368ff0f4ee84b99ad7fb47b1171a4"
);
table_module!(
    HttpMapping,
    "mapping-linux-http",
    "http.toml",
    "e5291149730ad786ff93559ce40c11973178440a3078490dcf984bdf684440f4"
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
