#![forbid(unsafe_code)]
//! Audit status/service tables; GKE additionally validates hierarchical resource paths.
mod gke;
pub use gke::GkeMapping;
use irmind_domain::EvidenceHash;
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_mapping_tables::TableMapping;
const CLOUD: &str = include_str!("cloud.toml");
const CLOUD_DIGEST: &str = "9bbdd74600a9b03315e3743dc6c173cadc379f663914dbc1adcbf36ec7ad69d2";
pub struct CloudAuditMapping(TableMapping);
impl CloudAuditMapping {
    pub fn for_capture() -> Result<Self, MappingError> {
        let decoder =
            irmind_domain::SourceDecoderIdentityV1::try_new("query-bigquery-cloud-audit", "1")
                .map_err(|_| MappingError::UnsupportedDecoder)?;
        Self::new()?
            .0
            .capture_alias("mapping-gcp-audit-query", &decoder)
            .map(Self)
    }

    pub fn new() -> Result<Self, MappingError> {
        TableMapping::bundled(
            CLOUD,
            &EvidenceHash::parse(CLOUD_DIGEST).map_err(|_| MappingError::InvalidDefinition)?,
        )
        .map(Self)
    }
}
impl SourceMapper for CloudAuditMapping {
    fn manifest(&self) -> &MappingManifest {
        self.0.manifest()
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.0.map(source)
    }
}
static CLOUD_MODULE: ModuleManifest = module("mapping-gcp-audit");
static GKE_MODULE: ModuleManifest = module("mapping-gke-audit");
const fn module(id: &'static str) -> ModuleManifest {
    ModuleManifest {
        id,
        version: "0.1.0",
        ports: &[ModulePort::SourceMapper],
        tools: &[],
        config: &[],
    }
}
impl MappingModule for CloudAuditMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        &CLOUD_MODULE
    }
}
impl MappingModule for GkeMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        &GKE_MODULE
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
