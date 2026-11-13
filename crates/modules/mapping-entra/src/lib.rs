#![forbid(unsafe_code)]
//! Included Entra tables plus bounded dynamic-field and status representation glue.
mod projection;
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingError, MappingIdentityV1, MappingManifest, MappingOutput, MappingProvenance,
        SourceMapper, SourceRecordV1,
    },
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct EntraMapping {
    manifest: MappingManifest,
    module: &'static ModuleManifest,
    base: TableMapping,
    status: Option<TableMapping>,
    format: &'static str,
}
struct Definition {
    module: ModuleManifest,
    format: &'static str,
    base: &'static str,
    status: Option<&'static str>,
}
impl EntraMapping {
    pub fn all() -> Result<Vec<Self>, MappingError> {
        DEFINITIONS.iter().map(Self::new).collect()
    }
    fn new(definition: &'static Definition) -> Result<Self, MappingError> {
        let base = compile(definition.base)?;
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            definition.module.id,
            &format!("entra-v1-{}", digest.as_str()),
            COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        Ok(Self {
            manifest: MappingManifest::try_new(
                identity,
                SourceMapper::manifest(&base).selectors().to_vec(),
                MappingProvenance::NativeBuild {
                    manifest: BUILD.to_vec(),
                },
                false,
            )?,
            module: &definition.module,
            base,
            status: definition.status.map(compile).transpose()?,
            format: definition.format,
        })
    }
}
impl SourceMapper for EntraMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let output = self.base.map(source)?;
        let partition = output.partition().clone();
        let mut record = output.into_record();
        let (common, diagnostics) =
            projection::project(source, self.format, &record.common, self.status.as_ref())?;
        record.common = common;
        MappingOutput::try_new(
            source,
            record.indexed,
            record.common,
            partition,
            diagnostics,
        )
    }
}
impl Module for EntraMapping {
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
fn compile(contents: &str) -> Result<TableMapping, MappingError> {
    let reviewed = TableMapping::review(contents)?;
    TableMapping::bundled(contents, reviewed.identity().implementation())
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
static DEFINITIONS: &[Definition] = &[
    Definition {
        module: module("mapping-entra-signin-resource"),
        format: "entra-signin-resource",
        base: include_str!("tables/signin-resource.toml"),
        status: Some(include_str!("tables/signin-resource-status.toml")),
    },
    Definition {
        module: module("mapping-entra-signin-table"),
        format: "entra-signin-table",
        base: include_str!("tables/signin-table.toml"),
        status: None,
    },
    Definition {
        module: module("mapping-entra-audit-resource"),
        format: "entra-audit-resource",
        base: include_str!("tables/audit-resource.toml"),
        status: Some(include_str!("tables/audit-resource-status.toml")),
    },
    Definition {
        module: module("mapping-entra-audit-table"),
        format: "entra-audit-table",
        base: include_str!("tables/audit-table.toml"),
        status: Some(include_str!("tables/audit-table-status.toml")),
    },
];
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
