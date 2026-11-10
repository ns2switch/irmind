#![forbid(unsafe_code)]
//! Unclassified syslog extraction. Priority bits and header aliases do not imply event categories.
mod record;
use irmind_app::{
    IndexedGraphRecord, PartitionProfile, SourceMapper,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingPartition, MappingProvenance, SourceRecordV1, SourceSelector, SourceValue,
    },
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct SyslogExtractionMapping {
    manifest: MappingManifest,
}
impl SyslogExtractionMapping {
    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let version = format!("syslog-extraction-v1-{}", digest.as_str());
        let identity = MappingIdentityV1::try_new(
            "mapping-syslog-extraction",
            &version,
            COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let selector = SourceSelector::try_new(
            "parser-syslog",
            BTreeSet::from(["syslog-source-v1".into()]),
            None,
            BTreeMap::new(),
            Vec::new(),
        )?;
        Ok(Self {
            manifest: MappingManifest::try_new(
                identity,
                vec![selector],
                MappingProvenance::NativeBuild {
                    manifest: BUILD.to_vec(),
                },
                true,
            )?,
        })
    }
}
impl SourceMapper for SyslogExtractionMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        if !self
            .manifest
            .selectors()
            .iter()
            .any(|selector| selector.matches(source))
        {
            return Err(MappingError::UnsupportedSourceValue);
        }
        let graph = record::project(source)?;
        let host = source
            .fields()
            .field("hostname")
            .and_then(SourceValue::as_text)
            .filter(|v| *v != "-")
            .unwrap_or("");
        MappingOutput::try_new(
            source,
            IndexedGraphRecord {
                record: graph,
                time: source.timestamp(),
                source_offset: source.origin().offset(),
            },
            MappingOutput::unclassified_common(source)?,
            MappingPartition::try_new(PartitionProfile::EndpointHost, "", "", host)?,
            vec![MappingDiagnostic::Unclassified],
        )
    }
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-syslog-extraction",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl Module for SyslogExtractionMapping {
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
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
