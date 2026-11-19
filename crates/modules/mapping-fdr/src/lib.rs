#![forbid(unsafe_code)]
//! Bundled finite FDR classification. Native glue retains unsupported optional
//! values with a visible coverage diagnostic and the validated partition host.
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingProvenance, SourceMapper, SourceRecordV1,
    },
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-fdr",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
pub struct FdrMapping {
    manifest: MappingManifest,
    tables: Vec<TableMapping>,
}
impl FdrMapping {
    pub fn new() -> Result<Self, MappingError> {
        let definitions = [include_str!("tables/fdr.toml")];
        let tables = definitions
            .into_iter()
            .map(|text| {
                let reviewed = TableMapping::review(text)?;
                TableMapping::bundled(text, reviewed.identity().implementation())
            })
            .collect::<Result<Vec<_>, MappingError>>()?;
        let hash = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            MODULE.id,
            &format!("fdr-v1-{}", hash.as_str()),
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
impl Module for FdrMapping {
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
impl SourceMapper for FdrMapping {
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
                let host = source
                    .fields()
                    .field("aid")
                    .and_then(irmind_app::source_mapping::SourceValue::as_text)
                    .ok_or(MappingError::UnsupportedSourceValue)?;
                let partition = irmind_app::source_mapping::MappingPartition::try_new(
                    irmind_app::PartitionProfile::EndpointHost,
                    "",
                    "",
                    host,
                )?;
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
            Ok(output)
                if output
                    .record()
                    .common
                    .event()
                    .categories()
                    .iter()
                    .next()
                    .is_none() =>
            {
                let partition = output.partition().clone();
                let record = output.into_record();
                MappingOutput::try_new(
                    source,
                    record.indexed,
                    record.common,
                    partition,
                    vec![MappingDiagnostic::Unclassified],
                )
            }
            other => other,
        }
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
