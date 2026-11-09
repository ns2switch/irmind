//! Cross-member auditd decoding requires bounded joins, beyond finite table rules.
use super::{
    Arc, EvidenceHash, MappingError, MappingManifest, MappingOutput, Module, ModuleConfig,
    ModuleManifest, ModulePort, ModuleRegistry, SourceMapper, SourceRecordV1,
};
use irmind_app::{
    IndexedGraphRecord, PartitionProfile,
    source_mapping::{
        MappingDiagnostic, MappingPartition, MappingProvenance, SourceDiscriminator,
        SourceSelector, SourceValue,
    },
};
use irmind_domain::{
    BoundedObservations, CategorySet, CommonEventV1, CommonField as F, CommonValue,
    EntityIdentityScope, EntityObservation, EntityRole as R, EventCategory, EventContextV1,
    EventHeaderV1, EventKind, EventOutcome, EventText, EventType, EventTypeSet, ObservedEntity,
    ObservedEntityKind,
};
use std::collections::{BTreeMap, BTreeSet};
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct AuditMapping {
    manifest: MappingManifest,
}
impl AuditMapping {
    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = irmind_domain::MappingIdentityV1::try_new(
            "mapping-linux-auditd",
            &format!("linux-auditd-v1-{}", digest.as_str()),
            irmind_domain::COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let selector = SourceSelector::try_new(
            "parser-linux",
            BTreeSet::from(["linux-source-v1".into()]),
            Some(("linux".into(), "linux-source-v1".into())),
            BTreeMap::from([(SourceDiscriminator::Dataset, "auditd".into())]),
            vec![],
        )?;
        Ok(Self {
            manifest: MappingManifest::try_new(
                identity,
                vec![selector],
                MappingProvenance::NativeBuild {
                    manifest: BUILD.to_vec(),
                },
                false,
            )?,
        })
    }
}
impl SourceMapper for AuditMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        if !self.manifest.selectors().iter().any(|s| s.matches(source)) {
            return Err(MappingError::UnsupportedSourceValue);
        }
        let SourceValue::Array(rows) = source.fields().field("records").ok_or_else(invalid)? else {
            return Err(invalid());
        };
        if rows.len() > 128 {
            return Err(invalid());
        }
        let mut calls = rows.iter().filter(|r| text(r, "type") == Some("SYSCALL"));
        let syscall = calls.next();
        if calls.next().is_some() {
            return Err(invalid());
        }
        let exec = rows.iter().any(|r| text(r, "type") == Some("EXECVE"));
        let header = header(source, syscall, exec)?;
        let mut mapped = Context::new(source);
        if let Some(row) = syscall {
            mapped.syscall(row)?;
        }
        let host = text(source.fields(), "node").unwrap_or("");
        mapped.text(
            F::HostName,
            Some(host),
            Some((ObservedEntityKind::Host, R::Observer)),
        )?;
        let common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
            mapped.fields,
            BoundedObservations::try_new(mapped.observations).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let unclassified = MappingOutput::unclassified(source, MappingDiagnostic::Unclassified)?;
        let indexed: IndexedGraphRecord = unclassified.record().indexed.clone();
        let output = MappingOutput::try_new(
            source,
            indexed,
            common,
            MappingPartition::try_new(PartitionProfile::EndpointHost, "", "", host)?,
            vec![],
        )?;
        Ok(output)
    }
}
fn header(
    source: &SourceRecordV1,
    syscall: Option<&SourceValue>,
    exec: bool,
) -> Result<EventHeaderV1, MappingError> {
    if syscall.is_none() && !exec {
        return Ok(EventHeaderV1::default());
    }
    let outcome = if source.annotations().partial() {
        EventOutcome::Unknown
    } else {
        match syscall.and_then(|s| text(s, "success")) {
            Some("yes") => EventOutcome::Success,
            Some("no") => EventOutcome::Failure,
            _ => EventOutcome::Unknown,
        }
    };
    let mut header = EventHeaderV1::new(
        CategorySet::new([if exec {
            EventCategory::Process
        } else {
            EventCategory::Api
        }]),
        EventTypeSet::new([if exec {
            EventType::Start
        } else {
            EventType::Info
        }]),
        outcome,
        EventKind::Event,
    );
    if let Some(action) = syscall.and_then(|s| text(s, "syscall")) {
        header = header.with_action(action).map_err(|_| invalid())?;
    }
    Ok(header)
}
struct Context<'a> {
    source: &'a SourceRecordV1,
    fields: EventContextV1,
    observations: Vec<EntityObservation>,
}
impl<'a> Context<'a> {
    fn new(source: &'a SourceRecordV1) -> Self {
        Self {
            source,
            fields: EventContextV1::default(),
            observations: vec![],
        }
    }
    fn syscall(&mut self, row: &SourceValue) -> Result<(), MappingError> {
        self.text(
            F::UserId,
            text(row, "uid"),
            Some((ObservedEntityKind::User, R::Actor)),
        )?;
        self.text(
            F::UserEffectiveId,
            text(row, "euid"),
            Some((ObservedEntityKind::User, R::Actor)),
        )?;
        self.text(
            F::UserTargetId,
            text(row, "obj_uid"),
            Some((ObservedEntityKind::User, R::Target)),
        )?;
        self.text(
            F::ProcessName,
            text(row, "comm"),
            Some((ObservedEntityKind::Process, R::Subject)),
        )?;
        self.text(F::ProcessExecutable, text(row, "exe"), None)?;
        for (name, field, role) in [
            ("pid", F::ProcessPid, R::Subject),
            ("ppid", F::ProcessParentPid, R::Parent),
        ] {
            if let Some(pid) = text(row, name) {
                let pid = pid.parse().map_err(|_| invalid())?;
                self.value(
                    field,
                    CommonValue::Unsigned(pid),
                    Some((ObservedEntityKind::Process, role)),
                )?;
            }
        }
        Ok(())
    }
    fn text(
        &mut self,
        field: F,
        value: Option<&str>,
        observation: Option<(ObservedEntityKind, R)>,
    ) -> Result<(), MappingError> {
        let Some(value) = value.filter(|s| !s.is_empty() && *s != "-" && *s != "(null)") else {
            return Ok(());
        };
        self.value(
            field,
            CommonValue::Text(EventText::new(value).map_err(|_| invalid())?),
            observation,
        )
    }
    fn value(
        &mut self,
        field: F,
        value: CommonValue,
        observation: Option<(ObservedEntityKind, R)>,
    ) -> Result<(), MappingError> {
        if let Some((kind, role)) = observation {
            let text = match &value {
                CommonValue::Text(t) => t.as_str().to_owned(),
                CommonValue::Unsigned(v) => v.to_string(),
                _ => return Err(invalid()),
            };
            let scope = EntityIdentityScope::SourceRecord {
                source: self.source.origin().source().clone(),
                record: self.source.origin().record(),
            };
            let entity = ObservedEntity::try_new(kind, &text, scope).map_err(|_| invalid())?;
            self.observations
                .push(EntityObservation::try_new(entity, role, field).map_err(|_| invalid())?);
        }
        self.fields.try_insert(field, value).map_err(|_| invalid())
    }
}
fn text<'a>(row: &'a SourceValue, key: &str) -> Option<&'a str> {
    row.field(key).and_then(SourceValue::as_text)
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
impl Module for AuditMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        const MODULE: ModuleManifest = ModuleManifest {
            id: "mapping-linux-auditd",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        };
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
