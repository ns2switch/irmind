#![forbid(unsafe_code)]
//! The finite tables interpret specific export schemas. Native dispatch binds
//! them to one signed module identity.
mod definitions;

use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{
        MappingError, MappingIdentityV1, MappingManifest, MappingOutput, MappingProvenance,
        SourceMapper, SourceRecordV1,
    },
};
use irmind_mapping_tables::TableMapping;

const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-macos",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};

pub struct MacosMapping {
    manifest: MappingManifest,
    tables: Vec<TableMapping>,
}

impl MacosMapping {
    pub fn new() -> Result<Self, MappingError> {
        let tables = definitions::BUNDLED
            .iter()
            .map(|text| {
                let reviewed = TableMapping::review(text)?;
                TableMapping::bundled(text, reviewed.identity().implementation())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selectors = tables
            .iter()
            .flat_map(|table| table.manifest().selectors().iter().cloned())
            .collect();
        let hash = EvidenceHash::from_bytes(irmind_mapping_contracts::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            MODULE.id,
            &format!("macos-v1-{}", hash.as_str()),
            COMMON_EVENT_V1,
            hash,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let manifest = MappingManifest::try_new(
            identity,
            selectors,
            MappingProvenance::NativeBuild {
                manifest: BUILD.to_vec(),
            },
            false,
        )?;
        Ok(Self { manifest, tables })
    }
}

impl MappingModule for MacosMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
}

impl SourceMapper for MacosMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }

    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let mut matches = self.tables.iter().filter(|table| {
            table
                .manifest()
                .selectors()
                .iter()
                .any(|s| s.matches(source))
        });
        let Some(table) = matches.next() else {
            return Err(MappingError::UnsupportedSourceValue);
        };
        if let Some(other) = matches.next() {
            return Err(MappingError::Ambiguous {
                first: table.manifest().identity().id().to_owned(),
                second: other.manifest().identity().id().to_owned(),
            });
        }
        table.map(source)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
