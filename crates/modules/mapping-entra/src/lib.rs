#![forbid(unsafe_code)]
//! Included Entra tables plus bounded dynamic-field and status representation glue.
mod projection;
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{
        MappingError, MappingIdentityV1, MappingManifest, MappingOutput, MappingProvenance,
        SourceMapper, SourceRecordV1,
    },
};
use irmind_mapping_tables::TableMapping;
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
    /// Reuse the local table mapper with a separately identified capture input.
    pub fn for_capture(
        format: &str,
        decoder: &irmind_domain::SourceDecoderIdentityV1,
    ) -> Result<Self, MappingError> {
        let definition = DEFINITIONS
            .iter()
            .find(|definition| definition.format == format)
            .ok_or(MappingError::UnsupportedDecoder)?;
        if !matches!(
            format,
            "entra-signin-table" | "entra-audit-table" | "azure-activity-table"
        ) {
            return Err(MappingError::UnsupportedDecoder);
        }
        let mut mapper = Self::new(definition)?;
        let id = format!("{}-query", definition.module.id);
        mapper.base = mapper.base.capture_alias(&format!("{id}-base"), decoder)?;
        mapper.status = mapper
            .status
            .as_ref()
            .map(|status| status.capture_alias(&format!("{id}-status"), decoder))
            .transpose()?;
        let mut build = BUILD.to_vec();
        build.extend_from_slice(b"\0irmind-analytics-capture-mapping-v1\0");
        build.extend_from_slice(decoder.id().as_bytes());
        build.push(0);
        build.extend_from_slice(decoder.version().as_bytes());
        let digest = EvidenceHash::from_bytes(irmind_mapping_contracts::sha256(&build));
        mapper.manifest = MappingManifest::try_new(
            MappingIdentityV1::try_new(
                &id,
                &format!("entra-v1-{}", digest.as_str()),
                COMMON_EVENT_V1,
                digest,
            )
            .map_err(|_| MappingError::InvalidManifest)?,
            SourceMapper::manifest(&mapper.base).selectors().to_vec(),
            MappingProvenance::NativeBuild { manifest: build },
            false,
        )?;
        Ok(mapper)
    }

    fn new(definition: &'static Definition) -> Result<Self, MappingError> {
        let base = compile(definition.base)?;
        let digest = EvidenceHash::from_bytes(irmind_mapping_contracts::sha256(BUILD));
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
        if self.format == "azure-activity-table" {
            return Ok(output);
        }
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
impl MappingModule for EntraMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        self.module
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
        module: module("mapping-azure-activity-table"),
        format: "azure-activity-table",
        base: include_str!("tables/azure-activity.toml"),
        status: None,
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
