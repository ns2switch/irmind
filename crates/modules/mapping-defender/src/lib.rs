#![forbid(unsafe_code)]
//! Bundled finite Defender tables. Native glue only selects the exact source
//! layout/table and retains unsupported optional values with a coverage notice.
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
    id: "mapping-defender",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
pub struct DefenderMapping {
    manifest: MappingManifest,
    tables: Vec<TableMapping>,
}
impl DefenderMapping {
    pub fn new() -> Result<Self, MappingError> {
        let definitions = [
            include_str!("tables/json-deviceprocessevents.toml"),
            include_str!("tables/json-devicenetworkevents.toml"),
            include_str!("tables/json-devicefileevents.toml"),
            include_str!("tables/json-deviceregistryevents.toml"),
            include_str!("tables/json-devicelogonevents.toml"),
            include_str!("tables/json-deviceimageloadevents.toml"),
            include_str!("tables/json-deviceevents.toml"),
            include_str!("tables/json-alertinfo.toml"),
            include_str!("tables/json-alertevidence.toml"),
            include_str!("tables/json-unknowndeviceevents.toml"),
            include_str!("tables/csv-deviceprocessevents.toml"),
            include_str!("tables/csv-devicenetworkevents.toml"),
            include_str!("tables/csv-devicefileevents.toml"),
            include_str!("tables/csv-deviceregistryevents.toml"),
            include_str!("tables/csv-devicelogonevents.toml"),
            include_str!("tables/csv-deviceimageloadevents.toml"),
            include_str!("tables/csv-deviceevents.toml"),
            include_str!("tables/csv-alertinfo.toml"),
            include_str!("tables/csv-alertevidence.toml"),
            include_str!("tables/csv-unknowndeviceevents.toml"),
            include_str!("tables/stream-deviceprocessevents.toml"),
            include_str!("tables/stream-devicenetworkevents.toml"),
            include_str!("tables/stream-devicefileevents.toml"),
            include_str!("tables/stream-deviceregistryevents.toml"),
            include_str!("tables/stream-devicelogonevents.toml"),
            include_str!("tables/stream-deviceimageloadevents.toml"),
            include_str!("tables/stream-deviceevents.toml"),
            include_str!("tables/stream-alertinfo.toml"),
            include_str!("tables/stream-alertevidence.toml"),
            include_str!("tables/stream-unknowndeviceevents.toml"),
        ];
        let tables = definitions
            .into_iter()
            .map(|text| {
                let reviewed = TableMapping::review(text)?;
                TableMapping::bundled(text, reviewed.identity().implementation())
            })
            .collect::<Result<Vec<_>, MappingError>>()?;
        let hash = EvidenceHash::from_bytes(irmind_mapping_contracts::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            MODULE.id,
            &format!("defender-v1-{}", hash.as_str()),
            COMMON_EVENT_V1,
            hash,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let selectors = tables
            .iter()
            .flat_map(|t| t.manifest().selectors().to_vec())
            .collect();
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
impl MappingModule for DefenderMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
}
impl SourceMapper for DefenderMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let mut matching = self
            .tables
            .iter()
            .filter(|t| t.manifest().selectors().iter().any(|s| s.matches(source)));
        let Some(table) = matching.next() else {
            return MappingOutput::unclassified(source, MappingDiagnostic::Unclassified);
        };
        if let Some(other) = matching.next() {
            return Err(MappingError::Ambiguous {
                first: table.manifest().identity().id().to_owned(),
                second: other.manifest().identity().id().to_owned(),
            });
        }
        match table.map(source) {
            Err(MappingError::UnsupportedSourceValue) => {
                let output =
                    MappingOutput::unclassified(source, MappingDiagnostic::UnsupportedValue)?;
                let partition = output.partition().clone();
                let mut record = output.into_record();
                if let Ok(header) = table.event_header(source) {
                    record.common = irmind_domain::CommonEventV1::try_new(
                        source.origin().clone(),
                        source.timestamp(),
                        header,
                        record.common.context().clone(),
                        record.common.observations().clone(),
                    )
                    .map_err(|_| MappingError::InvalidOutput)?;
                }
                MappingOutput::try_new(
                    source,
                    record.indexed,
                    record.common,
                    partition,
                    vec![MappingDiagnostic::UnsupportedValue],
                )
            }
            other => other,
        }
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
