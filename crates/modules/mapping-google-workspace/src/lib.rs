#![forbid(unsafe_code)]
//! Operation names and outcomes use a finite table. The mapper resolves only
//! documented parameters whose positions vary within the native parameter list.
mod parameters;

use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingError, MappingIdentityV1, MappingManifest, MappingOutput, MappingProvenance,
        SourceMapper, SourceRecordV1,
    },
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;

const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-google-workspace",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};

pub struct GoogleWorkspaceMapping {
    manifest: MappingManifest,
    table: TableMapping,
}

impl GoogleWorkspaceMapping {
    pub fn new() -> Result<Self, MappingError> {
        let definition = include_str!("events.toml");
        let reviewed = TableMapping::review(definition)?;
        let table = TableMapping::bundled(definition, reviewed.identity().implementation())?;
        let hash = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            MODULE.id,
            &format!("google-workspace-v1-{}", hash.as_str()),
            COMMON_EVENT_V1,
            hash,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let manifest = MappingManifest::try_new(
            identity,
            table.manifest().selectors().to_vec(),
            MappingProvenance::NativeBuild {
                manifest: BUILD.to_vec(),
            },
            false,
        )?;
        Ok(Self { manifest, table })
    }
}

impl Module for GoogleWorkspaceMapping {
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

impl SourceMapper for GoogleWorkspaceMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }

    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        parameters::project(source, self.table.map(source)?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
