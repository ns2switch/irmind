#![forbid(unsafe_code)]
//! UDM `ProtoJSON` validation is native because repeated noun values require checked cardinality.
mod project;
use irmind_app::{
    SourceMapper,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingError, MappingIdentityV1, MappingManifest, MappingOutput, MappingProvenance,
        SourceRecordV1, SourceSelector,
    },
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct UdmMapping {
    manifest: MappingManifest,
}
impl UdmMapping {
    pub fn new() -> Result<Self, MappingError> {
        let hash = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            "mapping-udm",
            &format!("udm-v1-{}", hash.as_str()),
            COMMON_EVENT_V1,
            hash,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let selector = SourceSelector::try_new(
            "siem-chronicle",
            BTreeSet::from(["chronicle-source-v1".into()]),
            Some(("chronicle-udm".into(), "chronicle-source-v1".into())),
            BTreeMap::new(),
            vec![],
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
impl SourceMapper for UdmMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        if !self.manifest.selectors().iter().any(|s| s.matches(source)) {
            return Err(MappingError::UnsupportedSourceValue);
        }
        project::map(source)
    }
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-udm",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl Module for UdmMapping {
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
