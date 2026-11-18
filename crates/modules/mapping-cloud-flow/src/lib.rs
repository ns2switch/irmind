#![forbid(unsafe_code)]
//! Cloud network classification and explicit outcomes come from included finite tables.
//! Native glue validates provider-specific partition placeholders, never inferring a host.
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingPartition, MappingProvenance, SourceMapper, SourceRecordV1, SourceValue,
    },
};
use irmind_domain::{COMMON_EVENT_V1, CommonEventV1, EventHeaderV1, EvidenceHash};
mod projection;
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
#[derive(Clone, Copy)]
enum SourceKind {
    Aws,
    AzureVnet,
    AzureNsg,
    Gcp,
}
impl SourceKind {
    fn module(self) -> &'static ModuleManifest {
        match self {
            Self::Aws => &MODULES[0],
            Self::AzureVnet => &MODULES[1],
            Self::AzureNsg => &MODULES[2],
            Self::Gcp => &MODULES[3],
        }
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
static MODULES: [ModuleManifest; 4] = [
    module("mapping-vpc-flow"),
    module("mapping-azure-vnet-flow"),
    module("mapping-azure-nsg-flow"),
    module("mapping-gcp-flow"),
];
pub struct CloudFlowMapping {
    kind: SourceKind,
    manifest: MappingManifest,
    base: TableMapping,
    status: TableMapping,
}
fn bad<T>(_: T) -> MappingError {
    MappingError::UnsupportedSourceValue
}
fn table(text: &str) -> Result<TableMapping, MappingError> {
    let reviewed = TableMapping::review(text)?;
    TableMapping::bundled(text, reviewed.identity().implementation())
}
impl CloudFlowMapping {
    pub fn aws() -> Result<Self, MappingError> {
        Self::new(
            SourceKind::Aws,
            include_str!("tables/aws-fields.toml"),
            include_str!("tables/aws-outcome.toml"),
        )
    }
    pub fn gcp() -> Result<Self, MappingError> {
        Self::new(
            SourceKind::Gcp,
            include_str!("tables/gcp-fields.toml"),
            include_str!("tables/gcp-outcome.toml"),
        )
    }
    pub fn azure() -> Result<Vec<Self>, MappingError> {
        Ok(vec![
            Self::new(
                SourceKind::AzureVnet,
                include_str!("tables/azure-vnet-fields.toml"),
                include_str!("tables/azure-vnet-outcome.toml"),
            )?,
            Self::new(
                SourceKind::AzureNsg,
                include_str!("tables/azure-nsg-fields.toml"),
                include_str!("tables/azure-nsg-outcome.toml"),
            )?,
        ])
    }
    fn new(kind: SourceKind, base: &str, status: &str) -> Result<Self, MappingError> {
        let base = table(base)?;
        let status = table(status)?;
        let hash = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            kind.module().id,
            &format!("cloud-flow-v1-{}", hash.as_str()),
            COMMON_EVENT_V1,
            hash,
        )
        .map_err(bad)?;
        let manifest = MappingManifest::try_new(
            identity,
            base.manifest().selectors().to_vec(),
            MappingProvenance::NativeBuild {
                manifest: BUILD.to_vec(),
            },
            false,
        )?;
        Ok(Self {
            kind,
            manifest,
            base,
            status,
        })
    }
}
impl Module for CloudFlowMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        self.kind.module()
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), irmind_app::AppError> {
        registry.add_source_mapper(Arc::new(*self))
    }
}
impl SourceMapper for CloudFlowMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let (base, diagnostics) = match self.base.map(source) {
            Ok(base) => (base, vec![]),
            Err(MappingError::UnsupportedSourceValue) => (
                MappingOutput::unclassified(source, MappingDiagnostic::UnsupportedValue)?,
                vec![MappingDiagnostic::UnsupportedValue],
            ),
            Err(error) => return Err(error),
        };
        let mut record = base.into_record();
        let classification = self.base.event_header(source)?;
        let outcome = self.status.event_header(source)?.outcome();
        let mut header = EventHeaderV1::new(
            classification.categories(),
            classification.types(),
            outcome,
            classification.kind(),
        );
        if let Some(action) = classification.action() {
            header = header.with_action(action).map_err(bad)?;
        }
        let mut context = record.common.context().clone();
        let mut observations = record.common.observations().values().to_vec();
        let partition = projection::project(source, self.kind, &mut context, &mut observations)?;
        record.common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
            context,
            irmind_domain::BoundedObservations::try_new(observations).map_err(bad)?,
        )
        .map_err(bad)?;
        MappingOutput::try_new(
            source,
            record.indexed,
            record.common,
            partition,
            diagnostics,
        )
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
