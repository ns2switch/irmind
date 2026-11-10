#![forbid(unsafe_code)]
//! Extraction modules retain DFIR search aliases without assigning classifications or roles.
mod projection;
use irmind_app::{
    IndexedGraphRecord, PartitionProfile, SourceMapper,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingPartition, MappingProvenance, SourceRecordV1, SourceSelector,
    },
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct DfirExtractionMapping {
    manifest: MappingManifest,
    parser: &'static str,
    module: &'static ModuleManifest,
}
const PARSERS: &[&str] = &[
    "parser-velociraptor",
    "parser-hayabusa",
    "parser-chainsaw",
    "parser-plaso",
    "parser-eztools",
];
impl DfirExtractionMapping {
    pub fn new(parser: &'static str) -> Result<Self, MappingError> {
        let index = PARSERS
            .iter()
            .position(|p| *p == parser)
            .ok_or(MappingError::InvalidManifest)?;
        let module = MODULES.get(index).ok_or(MappingError::InvalidManifest)?;
        let short = parser
            .strip_prefix("parser-")
            .ok_or(MappingError::InvalidManifest)?;
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            &format!("mapping-{short}-extraction"),
            &format!("extraction-v1-{}", digest.as_str()),
            COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let selector = SourceSelector::try_new(
            parser,
            BTreeSet::from([format!("{short}-source-v1")]),
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
            parser,
            module,
        })
    }
    pub fn all() -> Result<Vec<Self>, MappingError> {
        PARSERS.iter().map(|&p| Self::new(p)).collect()
    }
}
impl SourceMapper for DfirExtractionMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        if !self.manifest.selectors().iter().any(|s| s.matches(source)) {
            return Err(MappingError::UnsupportedSourceValue);
        }
        let (record, host) = projection::project(self.parser, source)?;
        MappingOutput::try_new(
            source,
            IndexedGraphRecord {
                record,
                time: source.timestamp(),
                source_offset: source.origin().offset(),
            },
            MappingOutput::unclassified_common(source)?,
            MappingPartition::try_new(PartitionProfile::EndpointHost, "", "", host)?,
            vec![MappingDiagnostic::Unclassified],
        )
    }
}
const fn module(id: &'static str) -> ModuleManifest {
    ModuleManifest {
        id,
        version: "0.1.0",
        ports: &[ModulePort::SourceMapper],
        tools: &[],
        config: &[],
    }
}
static MODULES: [ModuleManifest; 5] = [
    module("mapping-velociraptor-extraction"),
    module("mapping-hayabusa-extraction"),
    module("mapping-chainsaw-extraction"),
    module("mapping-plaso-extraction"),
    module("mapping-eztools-extraction"),
];
impl Module for DfirExtractionMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        self.module
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
