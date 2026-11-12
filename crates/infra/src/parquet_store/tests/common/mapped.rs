//! Synthetic semantic mapping; the JSON decoder remains format-only.
use super::*;
use irmind_app::common_event::*;
use irmind_app::source_mapping::{
    MappingCatalog, MappingError, MappingManifest, MappingOutput, MappingPartition,
    MappingProvenance, SourceRecordV1, SourceSelector, SourceValue,
};
use irmind_app::{IndexedGraphRecord, SourceMapper};
use irmind_domain::EvidenceHash;
use std::{collections::BTreeSet, sync::Arc};

struct Mapper {
    manifest: MappingManifest,
}
impl Mapper {
    fn new() -> Self {
        let bytes = b"synthetic-common-mapping-v1";
        Self {
            manifest: MappingManifest::try_new(
                irmind_domain::MappingIdentityV1::try_new(
                    "mapping-synthetic",
                    "1",
                    irmind_domain::COMMON_EVENT_V1,
                    EvidenceHash::from_bytes(irmind_app::sha256(bytes)),
                )
                .unwrap(),
                vec![
                    SourceSelector::try_new(
                        "parser-json",
                        BTreeSet::from(["json-source-v1".into()]),
                        None,
                        BTreeMap::new(),
                        vec![],
                    )
                    .unwrap(),
                ],
                MappingProvenance::NativeBuild {
                    manifest: bytes.to_vec(),
                },
                false,
            )
            .unwrap(),
        }
    }
}
fn catalog() -> Arc<MappingCatalog> {
    let catalog = MappingCatalog::freeze(
        vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
        vec![Arc::new(Mapper::new())],
    )
    .unwrap();
    Arc::new(catalog)
}
pub(super) fn store(root: &Path) -> ParquetStore {
    ParquetStore::open_mapped(root, catalog()).unwrap()
}
pub(super) fn compat_store(root: &Path) -> ParquetStore {
    let catalog = MappingCatalog::freeze(
        vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
        vec![Arc::new(
            irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap(),
        )],
    )
    .unwrap();
    ParquetStore::open_mapped(root, Arc::new(catalog)).unwrap()
}
fn field<'a>(source: &'a SourceRecordV1, key: &str) -> Option<&'a SourceValue> {
    match source.fields() {
        SourceValue::Object(fields) => fields.get(key),
        _ => None,
    }
}
fn text<'a>(source: &'a SourceRecordV1, key: &str) -> Option<&'a str> {
    match field(source, key) {
        Some(SourceValue::Text(value)) => Some(value),
        _ => None,
    }
}
impl SourceMapper for Mapper {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    #[allow(clippy::too_many_lines)]
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let invalid = || MappingError::InvalidOutput;
        let action = text(source, "eventName").unwrap_or("");
        let outcome = text(source, "outcome")
            .map(EventOutcome::parse)
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or(EventOutcome::Unknown);
        let header = EventHeaderV1::new(
            CategorySet::new([EventCategory::Authentication]),
            EventTypeSet::new([EventType::Start]),
            outcome,
            EventKind::Event,
        )
        .with_action(action)
        .map_err(|_| invalid())?;
        let mut context = EventContextV1::default();
        let mut observations = Vec::new();
        for (key, common, role) in [
            ("source_ip", CommonField::SourceIp, EntityRole::Source),
            (
                "destination_ip",
                CommonField::DestinationIp,
                EntityRole::Destination,
            ),
        ] {
            if let Some(value) = text(source, key) {
                context
                    .try_insert(
                        common,
                        CommonValue::Ip(value.parse().map_err(|_| invalid())?),
                    )
                    .map_err(|_| invalid())?;
                let entity = ObservedEntity::try_new(
                    ObservedEntityKind::Ip,
                    value,
                    EntityIdentityScope::Global,
                )
                .map_err(|_| invalid())?;
                observations
                    .push(EntityObservation::try_new(entity, role, common).map_err(|_| invalid())?);
            }
        }
        if let Some(SourceValue::Number(value)) = field(source, "pid") {
            let pid = value.as_str().parse::<u64>().map_err(|_| invalid())?;
            context
                .try_insert(CommonField::ProcessPid, CommonValue::Unsigned(pid))
                .map_err(|_| invalid())?;
            let scope = EntityIdentityScope::SourceRecord {
                source: source.origin().source().clone(),
                record: source.origin().record(),
            };
            let entity =
                ObservedEntity::try_new(ObservedEntityKind::Process, &pid.to_string(), scope)
                    .map_err(|_| invalid())?;
            observations.push(
                EntityObservation::try_new(entity, EntityRole::Subject, CommonField::ProcessPid)
                    .map_err(|_| invalid())?,
            );
        }
        let common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
            context,
            BoundedObservations::try_new(observations).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let record = irmind_app::GraphRecord {
            index: usize::try_from(source.origin().record()).map_err(|_| invalid())?,
            at: source
                .timestamp()
                .map_or_else(String::new, irmind_app::IndexedTime::to_rfc3339),
            event: action.into(),
            text: irmind_app::source_mapping::json::render_source_fields(source.fields())
                .map_err(|_| invalid())?,
            entities: vec![],
            relations: vec![],
        };
        MappingOutput::try_new(
            source,
            IndexedGraphRecord {
                record,
                time: source.timestamp(),
                source_offset: source.origin().offset(),
            },
            common,
            MappingPartition::default(),
            vec![],
        )
    }
}

/// Signed reconstruction requires the original source sets and mapping receipts;
/// an unsigned physical projection must never take the historical parser path.
pub(super) fn assert_rebuild(root: &Path, paths: &[String], compact: bool) {
    use irmind_app::{
        AuditLog as _, CryptoPorts, Engine, EnginePorts, LargeCaseUseCases, ParserSelection,
    };
    let store = Arc::new(crate::LocalStore::open_mapped(root, catalog()).unwrap());
    let signer = Arc::new(crate::LocalSigner {
        key: ed25519_dalek::SigningKey::from_bytes(&[88; 32]),
        actor: irmind_domain::Actor::Analyst,
    });
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(crate::LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        ),
        irmind_domain::ExecutionMode::Attended,
        Arc::new(crate::SystemClock),
    )
    .unwrap();
    let id = engine
        .create_case("Synthetic typed reconstruction", "local only")
        .unwrap()
        .id;
    let selections = paths
        .iter()
        .map(|path| {
            let raw = fs::read(root.join(path)).unwrap();
            (
                path.clone(),
                ParserSelection {
                    parser_id: "parser-json".into(),
                    parser_version: "json-source-v1".into(),
                    confidence: 90,
                    mode: irmind_domain::ParserSelectionMode::Automatic,
                    timestamp_context: None,
                    format_sample_sha256: irmind_app::sha256(&raw[..raw.len().min(64 * 1024)]),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &crate::parquet_store::fixtures::parser(),
    };
    let cancel = CancellationToken::new();
    // Maintenance compaction combines successive ingests. Initial direct
    // ingestion already produces final files and has no inactive parents.
    for group in paths.chunks(if compact { 1 } else { paths.len() }) {
        large
            .ingest_local_batch_selected(&id, root, group, true, &selections, &cancel)
            .unwrap();
    }
    if compact {
        assert!(large.compact_case_with_threshold(&id, 2, &cancel).unwrap() > 0);
    }
    assert_eq!(
        large.verify_parquet_rebuild(&id, root, &cancel).unwrap(),
        paths.len()
    );
    let entries = store.entries(&id).unwrap();
    assert!(
        irmind_app::artifact_catalog(&entries)
            .unwrap()
            .all
            .iter()
            .all(|a| matches!(a, irmind_domain::ParquetArtifact::V3(_)))
    );
}
