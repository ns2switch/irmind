#![forbid(unsafe_code)]
//! Finite email/file rules are declarative. Native glue handles RFC mailbox lists
//! and literal URL extraction identities, which require bounded array handling.
mod projection;
mod urls;
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingProvenance, SourceMapper, SourceRecordV1,
    },
};
use irmind_mapping_tables::TableMapping;
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-email",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
pub struct EmailMapping {
    manifest: MappingManifest,
    table: TableMapping,
}
impl EmailMapping {
    pub fn new() -> Result<Self, MappingError> {
        let text = include_str!("tables/email.toml");
        let reviewed = TableMapping::review(text)?;
        let table = TableMapping::bundled(text, reviewed.identity().implementation())?;
        let hash = EvidenceHash::from_bytes(irmind_mapping_contracts::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            MODULE.id,
            &format!("email-v1-{}", hash.as_str()),
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
            true,
        )?;
        Ok(Self { manifest, table })
    }
}
impl MappingModule for EmailMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
}
impl SourceMapper for EmailMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let output = match self.table.map(source) {
            Ok(output) => output,
            Err(MappingError::UnsupportedSourceValue) => {
                return MappingOutput::unclassified(source, MappingDiagnostic::UnsupportedValue);
            }
            Err(error) => return Err(error),
        };
        projection::project(source, output)
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
