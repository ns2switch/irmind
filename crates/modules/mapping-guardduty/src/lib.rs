#![forbid(unsafe_code)]
//! Included tables classify every `GuardDuty` record as an unconfirmed source alert.
//! Native glue converts the exact numeric severity lexeme and validates IP variants.
use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingProvenance, SourceMapper, SourceRecordV1, SourceValue,
    },
};
use irmind_domain::{
    BoundedObservations, COMMON_EVENT_V1, CommonEventV1, CommonField as F, CommonValue,
    EntityIdentityScope, EntityObservation, EntityRole, EventText, EvidenceHash, ObservedEntity,
    ObservedEntityKind,
};
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-guardduty",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
pub struct GuardDutyMapping {
    manifest: MappingManifest,
    tables: [TableMapping; 2],
}
fn bad<T>(_: T) -> MappingError {
    MappingError::UnsupportedSourceValue
}
impl GuardDutyMapping {
    pub fn new() -> Result<Self, MappingError> {
        let tables = [
            include_str!("tables/wire.toml"),
            include_str!("tables/sdk.toml"),
        ]
        .map(|text| {
            let reviewed = TableMapping::review(text)?;
            TableMapping::bundled(text, reviewed.identity().implementation())
        });
        let [wire, sdk] = tables;
        let tables = [wire?, sdk?];
        let hash = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            MODULE.id,
            &format!("guardduty-v1-{}", hash.as_str()),
            COMMON_EVENT_V1,
            hash,
        )
        .map_err(bad)?;
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
impl Module for GuardDutyMapping {
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
impl SourceMapper for GuardDutyMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let sdk = source.format().id() == "guardduty-sdk";
        let table = &self.tables[usize::from(sdk)];
        let output = table.map(source)?;
        let partition = output.partition().clone();
        let mut record = output.into_record();
        let mut context = record.common.context().clone();
        let mut observations = record.common.observations().values().to_vec();
        let mut diagnostics = Vec::new();
        if let Some(SourceValue::Number(number)) =
            source
                .fields()
                .field(if sdk { "Severity" } else { "severity" })
        {
            context
                .try_insert(
                    F::IrmindDetectionSourceSeverity,
                    CommonValue::Text(EventText::new(number.as_str()).map_err(bad)?),
                )
                .map_err(bad)?;
        }
        project_endpoint(
            source.fields(),
            sdk,
            &mut context,
            &mut observations,
            &mut diagnostics,
        )?;
        record.common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            record.common.event().clone(),
            context,
            BoundedObservations::try_new(observations).map_err(bad)?,
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
fn project_endpoint(
    fields: &SourceValue,
    sdk: bool,
    context: &mut irmind_domain::EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    let keys = if sdk {
        [
            "Service",
            "Action",
            "AwsApiCallAction",
            "NetworkConnectionAction",
            "RemoteIpDetails",
            "IpAddressV4",
            "ConnectionDirection",
        ]
    } else {
        [
            "service",
            "action",
            "awsApiCallAction",
            "networkConnectionAction",
            "remoteIpDetails",
            "ipAddressV4",
            "connectionDirection",
        ]
    };
    let Some(action) = fields.field(keys[0]).and_then(|v| v.field(keys[1])) else {
        return Ok(());
    };
    for (name, api) in [(keys[2], true), (keys[3], false)] {
        let Some(details) = action.field(name) else {
            continue;
        };
        let Some(raw) = details
            .field(keys[4])
            .and_then(|v| v.field(keys[5]))
            .and_then(SourceValue::as_text)
        else {
            continue;
        };
        let endpoint = if api {
            Some((F::SourceIp, EntityRole::Source))
        } else {
            match details.field(keys[6]).and_then(SourceValue::as_text) {
                Some("INBOUND") => Some((F::SourceIp, EntityRole::Source)),
                Some("OUTBOUND") => Some((F::DestinationIp, EntityRole::Destination)),
                _ => None,
            }
        };
        if let (Ok(ip), Some((field, role))) = (raw.parse::<std::net::IpAddr>(), endpoint) {
            context
                .try_insert(field, CommonValue::Ip(ip))
                .map_err(bad)?;
            let entity = ObservedEntity::try_new(
                ObservedEntityKind::Ip,
                &ip.to_string(),
                EntityIdentityScope::Global,
            )
            .map_err(bad)?;
            observations.push(EntityObservation::try_new(entity, role, field).map_err(bad)?);
            break;
        }
        diagnostics.push(MappingDiagnostic::UnsupportedValue);
    }
    Ok(())
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
