use super::{
    EvidenceHash, MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1,
    TableMapping,
};
use irmind_domain::{
    BoundedObservations, CategorySet, CommonEventV1, CommonField as F, CommonValue,
    EntityIdentityScope, EntityObservation, EntityRole, EventCategory, EventContextV1,
    EventHeaderV1, EventKind, EventOutcome, EventText, EventType, EventTypeSet, ObservedEntity,
    ObservedEntityKind,
};
use irmind_mapping_contracts::{
    common_event::cluster_audit::{self, AuditExactField},
    source_mapping::{MappingIdentityV1, MappingProvenance},
};
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
const BASE: &str = include_str!("gke.toml");
const BASE_DIGEST: &str = "0114a289c7b4a50c8c37dd2f3f721f38166506874add399cbb415fb03defcbcf";
pub struct GkeMapping {
    base: TableMapping,
    manifest: MappingManifest,
}
impl GkeMapping {
    pub fn new() -> Result<Self, MappingError> {
        let base = TableMapping::bundled(
            BASE,
            &EvidenceHash::parse(BASE_DIGEST).map_err(|_| MappingError::InvalidDefinition)?,
        )?;
        let digest = EvidenceHash::from_bytes(irmind_mapping_contracts::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            "mapping-gke-audit",
            &format!("gke-paths-v2-{}", digest.as_str()),
            irmind_domain::COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| MappingError::InvalidManifest)?;
        let manifest = MappingManifest::try_new(
            identity,
            SourceMapper::manifest(&base).selectors().to_vec(),
            MappingProvenance::NativeBuild {
                manifest: BUILD.to_vec(),
            },
            false,
        )?;
        Ok(Self { base, manifest })
    }
}
impl SourceMapper for GkeMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let output = self.base.project_cluster_audit(source)?;
        let partition = output.partition().clone();
        let mut record = output.into_record();
        let mut context = record.common.context().clone();
        let mut observations = record.common.observations().values().to_vec();
        omit_invalid_enrichment(&mut context, &mut observations, |context, _| {
            regional_location(source, context)
        })?;
        omit_invalid_enrichment(&mut context, &mut observations, |context, observations| {
            resource(source, context, observations)
        })?;
        let header = record.common.event();
        let header = if header.categories().iter().next().is_none() {
            let fallback = EventHeaderV1::new(
                CategorySet::new([EventCategory::Api]),
                EventTypeSet::new([EventType::Access]),
                EventOutcome::Unknown,
                EventKind::Event,
            );
            match header.action() {
                Some(action) => fallback.with_action(action).map_err(bad)?,
                None => fallback,
            }
        } else {
            header.clone()
        };
        record.common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
            context,
            BoundedObservations::try_new(observations).map_err(bad)?,
        )
        .map_err(bad)?;
        record.indexed.record.text =
            cluster_audit::encode(&record.common, source.fields(), AuditExactField::GkeStatus)
                .map_err(bad)?;
        MappingOutput::try_new(source, record.indexed, record.common, partition, vec![])
    }
}
fn omit_invalid_enrichment(
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    enrich: impl FnOnce(&mut EventContextV1, &mut Vec<EntityObservation>) -> Result<(), MappingError>,
) -> Result<(), MappingError> {
    let mut candidate_context = context.clone();
    let count = observations.len();
    match enrich(&mut candidate_context, observations) {
        Ok(()) => {
            *context = candidate_context;
            Ok(())
        }
        Err(MappingError::UnsupportedSourceValue) => {
            observations.truncate(count);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn resource(
    source: &SourceRecordV1,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
) -> Result<(), MappingError> {
    let Some(path) = source
        .fields()
        .field("protoPayload")
        .and_then(|p| p.field("resourceName"))
        .and_then(irmind_mapping_contracts::source_mapping::SourceValue::as_text)
    else {
        return Ok(());
    };
    if path.len() > 4096 {
        return Err(bad(()));
    }
    let parts = path.split('/').take(33).collect::<Vec<_>>();
    if parts.len() > 32
        || parts
            .iter()
            .any(|p| p.is_empty() || matches!(*p, "." | ".."))
    {
        return Err(bad(()));
    }
    let (kind, name, namespace) = match parts.as_slice() {
        [_, _, "namespaces", namespace, kind, name]
        | [_, _, "namespaces", namespace, kind, name, _] => (*kind, *name, Some(*namespace)),
        [_, _, "namespaces", name] => ("namespaces", *name, None),
        [_, _, "nodes", name] => ("nodes", *name, None),
        _ => return Ok(()),
    };
    insert(context, F::OrchestratorResourceType, kind)?;
    insert(context, F::OrchestratorResourceName, name)?;
    if let Some(namespace) = namespace {
        insert(context, F::OrchestratorNamespace, namespace)?;
        observe(
            source,
            observations,
            ObservedEntityKind::KubernetesNamespace,
            namespace,
            None,
            EntityRole::Subject,
            F::OrchestratorNamespace,
        )?;
    }
    if !matches!(parts.as_slice(), ["core", "v1", ..]) {
        return Ok(());
    }
    let entity = match kind {
        "pods" => ObservedEntityKind::KubernetesPod,
        "nodes" => ObservedEntityKind::KubernetesNode,
        "namespaces" => ObservedEntityKind::KubernetesNamespace,
        "serviceaccounts" => ObservedEntityKind::KubernetesServiceAccount,
        _ => return Ok(()),
    };
    observe(
        source,
        observations,
        entity,
        name,
        namespace,
        EntityRole::Target,
        F::OrchestratorResourceName,
    )
}
fn insert(context: &mut EventContextV1, field: F, value: &str) -> Result<(), MappingError> {
    context
        .try_insert(
            field,
            CommonValue::Text(EventText::new(value).map_err(bad)?),
        )
        .map_err(bad)
}
fn observe(
    source: &SourceRecordV1,
    observations: &mut Vec<EntityObservation>,
    kind: ObservedEntityKind,
    name: &str,
    namespace: Option<&str>,
    role: EntityRole,
    field: F,
) -> Result<(), MappingError> {
    let cluster = source.cluster_identity().ok_or_else(|| bad(()))?;
    let scope = EntityIdentityScope::cluster(cluster.clone(), namespace).map_err(bad)?;
    let entity = ObservedEntity::try_new(kind, name, scope).map_err(bad)?;
    observations.push(EntityObservation::try_new(entity, role, field).map_err(bad)?);
    Ok(())
}
fn bad<T>(_: T) -> MappingError {
    MappingError::UnsupportedSourceValue
}

// GKE location can be a zone. Retain its full value in the source/cluster identity;
// only a complete reported regional code is projected, never a derived parent.
fn regional_location(
    source: &SourceRecordV1,
    context: &mut EventContextV1,
) -> Result<(), MappingError> {
    let Some(location) = source
        .fields()
        .field("resource")
        .and_then(|v| v.field("labels"))
        .and_then(|v| v.field("location"))
        .and_then(irmind_mapping_contracts::source_mapping::SourceValue::as_text)
    else {
        return Ok(());
    };
    let Some((continent, area)) = location.split_once('-') else {
        return Ok(());
    };
    if !matches!(
        continent,
        "us" | "europe" | "asia" | "australia" | "northamerica" | "southamerica" | "africa" | "me"
    ) {
        return Ok(());
    }
    let letters = area.bytes().take_while(u8::is_ascii_lowercase).count();
    if letters > 0 && letters < area.len() && area[letters..].bytes().all(|b| b.is_ascii_digit()) {
        insert(context, F::CloudRegion, location)?;
    }
    Ok(())
}
