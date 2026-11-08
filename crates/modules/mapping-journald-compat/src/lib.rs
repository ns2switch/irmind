#![forbid(unsafe_code)]
//! Frozen multi-field journald compatibility projection, not a semantic classifier.
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
pub struct JournaldCompatibilityMapping {
    manifest: MappingManifest,
}
impl JournaldCompatibilityMapping {
    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let version = format!("journald-compat-v1-{}", digest.as_str());
        let identity = MappingIdentityV1::try_new(
            "mapping-journald-compat",
            &version,
            COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let selector = SourceSelector::try_new(
            "parser-linux",
            BTreeSet::from(["journald-source-v1".into()]),
            Some(("journald-json".into(), "journald-source-v1".into())),
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
impl SourceMapper for JournaldCompatibilityMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        for key in [
            "_HOSTNAME",
            "_UID",
            "_AUDIT_LOGINUID",
            "_EXE",
            "_COMM",
            "SYSLOG_IDENTIFIER",
            "_PID",
            "_CMDLINE",
        ] {
            if source
                .fields()
                .field(key)
                .is_some_and(|v| !matches!(v, SourceValue::Null | SourceValue::Text(_)))
            {
                return Err(MappingError::UnsupportedSourceValue);
            }
        }
        let graph = record::project(source)?;
        let host = source
            .fields()
            .field("_HOSTNAME")
            .and_then(SourceValue::as_text)
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
    id: "mapping-journald-compat",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl Module for JournaldCompatibilityMapping {
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
