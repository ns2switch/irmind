#![forbid(unsafe_code)]
//! Native ECS validation: closed arrays, typed values and explicit occurrence roles.
mod context;
mod header;
mod projection;
mod roles;
mod view;
use irmind_app::{
    IndexedGraphRecord, PartitionProfile, SourceMapper,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingPartition, MappingProvenance, SourceRecordV1, SourceSelector,
    },
};
use irmind_domain::{COMMON_EVENT_V1, CommonEventV1, EvidenceHash};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct EcsMapping {
    manifest: MappingManifest,
}
impl EcsMapping {
    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            "mapping-ecs",
            &format!("ecs-9.5-v1-{}", digest.as_str()),
            COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let selector = SourceSelector::try_new(
            "parser-ecs",
            BTreeSet::from(["ecs-source-v1".into()]),
            Some(("ecs".into(), "ecs-source-v1".into())),
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
impl SourceMapper for EcsMapping {
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
        let view = view::View(source.fields());
        let (header, mut diagnostics) = header::project(&view)?;
        let context = context::project(&view)?;
        let observations = roles::project(source, &context)?;
        let common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
            context,
            observations,
        )
        .map_err(|_| MappingError::UnsupportedSourceValue)?;
        let host = view.text("host.name")?.unwrap_or("");
        let record = projection::project(source, &view)?;
        if record.text.len() > irmind_domain::SOURCE_MAX_BYTES {
            return Err(MappingError::UnsupportedSourceValue);
        }
        if common.event().categories().bits() == 0 && common.event().types().bits() == 0 {
            diagnostics.push(MappingDiagnostic::Unclassified);
        }
        MappingOutput::try_new(
            source,
            IndexedGraphRecord {
                record,
                time: source.timestamp(),
                source_offset: source.origin().offset(),
            },
            common,
            MappingPartition::try_new(PartitionProfile::EndpointHost, "", "", host)?,
            diagnostics,
        )
    }
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-ecs",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl Module for EcsMapping {
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
