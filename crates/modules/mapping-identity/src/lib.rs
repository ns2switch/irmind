#![forbid(unsafe_code)]
//! Classification and outcome are finite TOML tables. Native glue only walks variable target/parameter arrays and validates IP representations.
use irmind_domain::{
    BoundedObservations, COMMON_EVENT_V1, CategorySet, CommonEventV1, CommonField as F,
    CommonValue, EntityIdentityScope, EntityObservation, EntityRole as R, EventCategory,
    EventHeaderV1, EventText, EvidenceHash, ObservedEntity, ObservedEntityKind as K,
};
use irmind_mapping_contracts::{
    modules::{MappingModule, ModuleManifest, ModulePort},
    source_mapping::{
        MappingDiagnostic, MappingError, MappingIdentityV1, MappingManifest, MappingOutput,
        MappingProvenance, SourceMapper, SourceRecordV1, SourceValue,
    },
};
use irmind_mapping_tables::TableMapping;
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct IdentityMapping {
    manifest: MappingManifest,
    module: &'static ModuleManifest,
    base: TableMapping,
    classify: TableMapping,
    status: TableMapping,
    source: &'static str,
}
static M365: ModuleManifest = ModuleManifest {
    id: "mapping-m365",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
static OKTA: ModuleManifest = ModuleManifest {
    id: "mapping-okta",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
fn bad<T>(_: T) -> MappingError {
    MappingError::UnsupportedSourceValue
}
fn table(s: &str) -> Result<TableMapping, MappingError> {
    let reviewed = TableMapping::review(s)?;
    TableMapping::bundled(s, reviewed.identity().implementation())
}
impl IdentityMapping {
    pub fn m365() -> Result<Self, MappingError> {
        Self::new(
            &M365,
            "m365",
            include_str!("tables/m365-base.toml"),
            include_str!("tables/m365-classification.toml"),
            include_str!("tables/m365-status.toml"),
        )
    }
    pub fn okta() -> Result<Self, MappingError> {
        Self::new(
            &OKTA,
            "okta",
            include_str!("tables/okta-base.toml"),
            include_str!("tables/okta-classification.toml"),
            include_str!("tables/okta-status.toml"),
        )
    }
    fn new(
        module: &'static ModuleManifest,
        source: &'static str,
        base: &str,
        classify: &str,
        status: &str,
    ) -> Result<Self, MappingError> {
        let base = table(base)?;
        let hash = EvidenceHash::from_bytes(irmind_mapping_contracts::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            module.id,
            &format!("identity-v1-{}", hash.as_str()),
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
            manifest,
            module,
            base,
            classify: table(classify)?,
            status: table(status)?,
            source,
        })
    }
}
impl MappingModule for IdentityMapping {
    fn module_manifest(&self) -> &'static ModuleManifest {
        self.module
    }
}
impl SourceMapper for IdentityMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let base = self.base.map(source)?;
        let partition = base.partition();
        let partition = if self.source == "m365" && partition.account() == "-" {
            irmind_mapping_contracts::source_mapping::MappingPartition::try_new(
                partition.profile(),
                "",
                partition.region(),
                partition.host(),
            )?
        } else {
            partition.clone()
        };
        let mut record = base.into_record();
        let class = self.classify.event_header(source)?;
        let status = self.status.event_header(source)?;
        let categories = if class.categories().bits() == 0 {
            CategorySet::new([EventCategory::Api])
        } else {
            class.categories()
        };
        let mut header =
            EventHeaderV1::new(categories, class.types(), status.outcome(), class.kind());
        if let Some(action) = record.common.event().action() {
            header = header.with_action(action).map_err(bad)?;
        }
        let mut context = record.common.context().clone();
        let mut observations = record.common.observations().values().to_vec();
        let mut diagnostics = Vec::new();
        let fields = source.fields();
        let scope = if self.source == "m365" {
            fields
                .field("OrganizationId")
                .and_then(SourceValue::as_text)
                .filter(|s| !matches!(*s, "" | "-"))
                .map(|s| EventText::identifier(s).map(EntityIdentityScope::Account))
                .transpose()
                .map_err(bad)?
                .unwrap_or_else(|| scope(source))
        } else {
            scope(source)
        };
        if self.source == "m365" {
            project_m365(fields, &scope, &mut observations, &mut diagnostics);
        }
        project_ip(
            self.source,
            fields,
            &mut context,
            &mut observations,
            &mut diagnostics,
        )?;
        if self.source == "okta" {
            project_okta_targets(
                fields,
                &scope,
                &mut context,
                &mut observations,
                &mut diagnostics,
            )?;
        }
        record.common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
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
fn project_m365(
    fields: &SourceValue,
    scope: &EntityIdentityScope,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) {
    // Keep account-bound observations when the source explicitly supplies its tenant.

    observations.retain(|o| o.entity().kind() != K::User && o.entity().kind() != K::Resource);
    if let Some(value) = fields.field("UserId").and_then(SourceValue::as_text) {
        observe(
            value,
            F::UserName,
            K::User,
            R::Actor,
            scope,
            observations,
            diagnostics,
        );
    }
    if let Some(value) = fields
        .field("MailboxOwnerUPN")
        .and_then(SourceValue::as_text)
    {
        observe(
            value,
            F::UserTargetName,
            K::User,
            R::Target,
            scope,
            observations,
            diagnostics,
        );
    }
    if let Some(value) = fields.field("ObjectId").and_then(SourceValue::as_text) {
        observe(
            value,
            F::IrmindResourceId,
            K::Resource,
            R::Target,
            scope,
            observations,
            diagnostics,
        );
    }
}
fn project_ip(
    name: &str,
    fields: &SourceValue,
    context: &mut irmind_domain::EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    let ip = if name == "m365" {
        fields
            .field("ClientIP")
            .or_else(|| fields.field("ClientIPAddress"))
    } else {
        fields.field("client").and_then(|v| v.field("ipAddress"))
    };
    if let Some(ip) = ip.and_then(SourceValue::as_text) {
        let parsed = ip
            .parse::<std::net::IpAddr>()
            .ok()
            .or_else(|| ip.parse::<std::net::SocketAddr>().ok().map(|v| v.ip()));
        if let Some(ip) = parsed {
            context
                .try_insert(F::SourceIp, CommonValue::Ip(ip))
                .map_err(bad)?;
            observe(
                &ip.to_string(),
                F::SourceIp,
                K::Ip,
                R::Source,
                &EntityIdentityScope::Global,
                observations,
                diagnostics,
            );
        } else if !ip.is_empty() {
            diagnostics.push(MappingDiagnostic::UnsupportedValue);
        }
    }

    Ok(())
}
fn project_okta_targets(
    fields: &SourceValue,
    scope: &EntityIdentityScope,
    context: &mut irmind_domain::EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    if let Some(SourceValue::Array(targets)) = fields.field("target") {
        for target in targets.iter().take(16) {
            let kind = target.field("type").and_then(SourceValue::as_text);
            if matches!(kind, Some("User" | "AppUser")) {
                for (key, field) in [("id", F::UserTargetId), ("alternateId", F::UserTargetName)] {
                    if let Some(value) = target
                        .field(key)
                        .and_then(SourceValue::as_text)
                        .filter(|v| !matches!(*v, "" | "-"))
                    {
                        if context.get(field).is_none() {
                            if let Ok(v) = EventText::new(value) {
                                context
                                    .try_insert(field, CommonValue::Text(v))
                                    .map_err(bad)?;
                                observe(
                                    value,
                                    field,
                                    K::User,
                                    R::Target,
                                    scope,
                                    observations,
                                    diagnostics,
                                );
                            }
                        } else if !matches!(context.get(field),Some(CommonValue::Text(v)) if v.as_str()==value)
                        {
                            diagnostics.push(MappingDiagnostic::UnsupportedValue);
                        }
                    }
                }
            }
        }
        if targets.len() > 16 {
            diagnostics.push(MappingDiagnostic::UnsupportedValue);
        }
    }

    Ok(())
}
fn scope(source: &SourceRecordV1) -> EntityIdentityScope {
    EntityIdentityScope::SourceRecord {
        source: source.origin().source().clone(),
        record: source.origin().record(),
    }
}
fn observe(
    value: &str,
    field: F,
    kind: K,
    role: R,
    scope: &EntityIdentityScope,
    out: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) {
    if value.is_empty() || value == "-" {
        return;
    }
    if out.len() >= 32 {
        diagnostics.push(MappingDiagnostic::UnsupportedValue);
        return;
    }
    match ObservedEntity::try_new(kind, value, scope.clone())
        .and_then(|e| EntityObservation::try_new(e, role, field))
    {
        Ok(v) => {
            if !out.contains(&v) {
                out.push(v);
            }
        }
        Err(_) => diagnostics.push(MappingDiagnostic::UnsupportedValue),
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
