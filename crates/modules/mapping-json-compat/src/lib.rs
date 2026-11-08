#![forbid(unsafe_code)]
//! Extraction-only baseline. Recursive aliases/relations exceed finite table rules;
//! no categories, outcomes or roles are inferred by this mapping.
mod classifier;
mod extract;
mod hunteval;
mod partition;
mod relations;
mod view;
use irmind_app::{
    GraphRecord, IndexedGraphRecord, SourceMapper,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingProvenance, SourceRecordV1, SourceSelector, SourceValue,
        json::{SourceJsonLimits, decode_json_fields, render_source_fields},
    },
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use view::LegacyView;

const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct JsonCompatibilityMapping {
    manifest: MappingManifest,
}
impl JsonCompatibilityMapping {
    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let version = format!("json-compat-v1-{}", digest.as_str());
        let identity =
            MappingIdentityV1::try_new("mapping-json-compat", &version, COMMON_EVENT_V1, digest)
                .map_err(|_| MappingError::InvalidManifest)?;
        let selector = SourceSelector::try_new(
            "parser-json",
            BTreeSet::from(["json-source-v1".into()]),
            Some(("json".into(), "source-json-v1".into())),
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
impl SourceMapper for JsonCompatibilityMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let value = normalize(source.fields());
        let extract::Projection {
            entities,
            relations,
        } = extract::entities(&value, source.origin().source().as_str())?;
        let partition = partition::project(&value, &entities)?;
        let graph = GraphRecord {
            index: usize::try_from(source.origin().record())
                .map_err(|_| MappingError::InvalidOutput)?,
            at: source
                .timestamp()
                .map_or_else(String::new, irmind_domain::IndexedTime::to_rfc3339),
            event: action(&value).into(),
            text: render_source_fields(&value).map_err(|_| MappingError::InvalidOutput)?,
            entities,
            relations,
        };
        MappingOutput::try_new(
            source,
            IndexedGraphRecord {
                record: graph,
                time: source.timestamp(),
                source_offset: source.origin().offset(),
            },
            MappingOutput::unclassified_common(source)?,
            partition,
            vec![MappingDiagnostic::Unclassified],
        )
    }
}
fn normalize(value: &SourceValue) -> Cow<'_, SourceValue> {
    if let Some(result @ SourceValue::Object(_)) = value.get("result") {
        if let Some(raw) = result.get("_raw").and_then(SourceValue::as_str)
            && let Ok(decoded) = decode_json_fields(raw.as_bytes(), SourceJsonLimits::default())
        {
            return Cow::Owned(decoded);
        }
        return Cow::Borrowed(result);
    }
    Cow::Borrowed(value)
}
fn action(value: &SourceValue) -> &str {
    [
        "/event_name",
        "/eventName",
        "/eventType",
        "/action",
        "/protoPayload/methodName",
        "/operationName/value",
        "/operationName",
    ]
    .iter()
    .find_map(|path| value.pointer(path))
    .and_then(SourceValue::as_str)
    .unwrap_or("record")
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-json-compat",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl Module for JsonCompatibilityMapping {
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
