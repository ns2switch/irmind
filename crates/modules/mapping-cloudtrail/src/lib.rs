#![forbid(unsafe_code)]
//! Bundled, finite `CloudTrail` classifications. No I/O, clock or credential ports.
use irmind_domain::EvidenceHash;
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_mapping_tables::TableMapping;
const DEFINITION: &str = include_str!("cloudtrail.toml");
const DIGEST: &str = "a1d8d85bd6d8aee0e9246fde59f46d779532066b9310d0e1c7246e812bec2ab5";
pub struct CloudTrailMapping(TableMapping);
impl CloudTrailMapping {
    pub fn for_capture() -> Result<Self, MappingError> {
        let decoder =
            irmind_domain::SourceDecoderIdentityV1::try_new("query-athena-cloudtrail", "1")
                .map_err(|_| MappingError::UnsupportedDecoder)?;
        Self::new()?
            .0
            .capture_alias("mapping-cloudtrail-query", &decoder)
            .map(Self)
    }

    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::parse(DIGEST).map_err(|_| MappingError::InvalidDefinition)?;
        TableMapping::bundled(DEFINITION, &digest).map(Self)
    }
}
impl SourceMapper for CloudTrailMapping {
    fn manifest(&self) -> &MappingManifest {
        self.0.manifest()
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.0.map(source)
    }
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-cloudtrail",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl MappingModule for CloudTrailMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
