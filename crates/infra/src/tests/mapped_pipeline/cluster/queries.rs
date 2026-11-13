use super::*;
use irmind_app::source_mapping::{
    MappingError, MappingIdentityV1, MappingManifest, MappingOutput, MappingPartition,
    MappingProvenance, SourceSelector,
};
use irmind_app::{IndexedGraphRecord, SourceMapper};
use irmind_domain::{
    BoundedObservations, CategorySet, CommonEventFilter, CommonEventV1, CommonField, CommonValue,
    EntityIdentityScope, EntityObservation, EntityRole, EventCategory, EventContextV1,
    EventHeaderV1, EventKind, EventOutcome, EventText, EventType, EventTypeSet, ObservedEntity,
    ObservedEntityKind,
};
use std::collections::BTreeSet;
struct Mapper {
    manifest: MappingManifest,
}
impl Mapper {
    fn new() -> Self {
        let bytes = b"synthetic-cluster-query-mapping-v1";
        Self {
            manifest: MappingManifest::try_new(
                MappingIdentityV1::try_new(
                    "mapping-cluster-test",
                    "1",
                    irmind_domain::COMMON_EVENT_V1,
                    irmind_domain::EvidenceHash::from_bytes(sha256(bytes)),
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
fn text<'a>(record: &'a SourceRecordV1, key: &str) -> Result<&'a str, MappingError> {
    record
        .fields()
        .field(key)
        .and_then(irmind_app::source_mapping::SourceValue::as_text)
        .ok_or(MappingError::InvalidOutput)
}
impl SourceMapper for Mapper {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let bad = |_| MappingError::InvalidOutput;
        let cluster = source
            .cluster_identity()
            .ok_or(MappingError::InvalidOutput)?;
        let namespace = text(source, "namespace")?;
        let mut context = EventContextV1::default();
        for (field, value) in [
            (
                CommonField::IrmindClusterIdentity,
                cluster.qualified().as_str(),
            ),
            (CommonField::OrchestratorNamespace, namespace),
            (CommonField::IrmindKubernetesPod, text(source, "pod")?),
            (CommonField::UserName, text(source, "actor")?),
        ] {
            context
                .try_insert(
                    field,
                    CommonValue::Text(EventText::new(value).map_err(bad)?),
                )
                .map_err(bad)?;
        }
        let pod = ObservedEntity::try_new(
            ObservedEntityKind::KubernetesPod,
            text(source, "pod")?,
            EntityIdentityScope::Cluster {
                cluster: cluster.clone(),
                namespace: Some(EventText::identifier(namespace).map_err(bad)?),
            },
        )
        .map_err(bad)?;
        let actor = ObservedEntity::try_new(
            ObservedEntityKind::KubernetesUser,
            text(source, "actor")?,
            EntityIdentityScope::Cluster {
                cluster: cluster.clone(),
                namespace: None,
            },
        )
        .map_err(bad)?;
        let observations = BoundedObservations::try_new(vec![
            EntityObservation::try_new(pod, EntityRole::Target, CommonField::IrmindKubernetesPod)
                .map_err(bad)?,
            EntityObservation::try_new(actor, EntityRole::Actor, CommonField::UserName)
                .map_err(bad)?,
        ])
        .map_err(bad)?;
        let common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            EventHeaderV1::new(
                CategorySet::new([EventCategory::Authentication]),
                EventTypeSet::new([EventType::Denied]),
                EventOutcome::Failure,
                EventKind::Event,
            ),
            context,
            observations,
        )
        .map_err(bad)?;
        let indexed = indexed(source, namespace)?;
        MappingOutput::try_new(
            source,
            indexed,
            common,
            MappingPartition::try_new(irmind_app::PartitionProfile::KubernetesCluster, "", "", "")?
                .with_cluster(cluster)?,
            vec![],
        )
    }
}
fn named_context(name: &str) -> SourceClusterContext {
    SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(
            ClusterIdentity::try_new(ClusterProvider::Kubernetes, &format!("urn:k8s:{name}"))
                .unwrap(),
            ClusterContextBasis::Analyst,
            None,
        )
        .unwrap(),
    ])
    .unwrap()
}
fn ingest_cluster(
    large: &LargeCaseUseCases<'_, '_>,
    root: &Path,
    case: &CaseId,
    name: &str,
    context: &SourceClusterContext,
    second: u8,
    namespace: &str,
) {
    let bytes = format!(
        r#"{{"eventTime":"2026-11-01T00:00:{second:02}Z","actor":"alice","namespace":"{namespace}","pod":"frontend"}}"#
    );
    fs::write(root.join(name), &bytes).unwrap();
    large
        .ingest_local_batch_selected(
            case,
            root,
            &[name.into()],
            false,
            &BTreeMap::from([(
                name.into(),
                ParserSelection {
                    parser_id: "parser-json".into(),
                    parser_version: "json-source-v1".into(),
                    confidence: 90,
                    mode: ParserSelectionMode::Analyst,
                    timestamp_context: None,
                    cluster_context: Some(context.clone()),
                    format_sample_sha256: sha256(bytes.as_bytes()),
                },
            )]),
            &CancellationToken::new(),
        )
        .unwrap();
}
#[test]
fn cluster_filters_isolate_lookup_neighbors_timeline_search_and_paths() {
    let root = tempfile::tempdir().unwrap();
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(ContextDecoder)],
            vec![Arc::new(Mapper::new())],
        )
        .unwrap(),
    );
    let (store, engine, catalog) = fixture_catalog(root.path(), catalog);
    let case = engine
        .create_case("Synthetic cluster query isolation", "local only")
        .unwrap();
    ingest_sources(store.as_ref(), &engine, &catalog, &case.id, root.path());
    let filter = GraphQueryFilter::default()
        .with_cluster("kubernetes:urn:k8s:a")
        .unwrap()
        .with_common(CommonEventFilter {
            category: Some(EventCategory::Authentication),
            outcome: Some(EventOutcome::Failure),
            ..CommonEventFilter::default()
        });
    assert_eq!(
        store
            .timeline_filtered(&case.id, &filter, 10)
            .unwrap()
            .len(),
        2
    );
    let lookup = store
        .entity_lookup_filtered(&case.id, &filter, "k8s_pod", "frontend")
        .unwrap();
    assert!(lookup.contains("observations=2"), "{lookup}");
    let path = store
        .graph_path_filtered(
            &case.id,
            &filter,
            ("k8s_pod", "frontend"),
            ("k8s_user", "alice"),
        )
        .unwrap();
    assert!(path.contains("co-observed"), "{path}");
    for result in [
        store
            .neighbors_filtered(&case.id, &filter, "k8s_pod", "frontend", 20)
            .unwrap(),
        store
            .entity_timeline_filtered(&case.id, &filter, "k8s_pod", "frontend", 20)
            .unwrap(),
        path,
        store
            .text_search_filtered(&case.id, &filter, "frontend", 20)
            .unwrap(),
    ] {
        assert!(!result.contains("urn:k8s:b"), "{result}");
        assert!(!result.contains("source-1.json"), "{result}");
    }
    verify_and_export(store.as_ref(), &engine, &catalog, &case.id, root.path());
}

fn indexed(source: &SourceRecordV1, namespace: &str) -> Result<IndexedGraphRecord, MappingError> {
    Ok(IndexedGraphRecord {
        record: irmind_app::GraphRecord {
            index: usize::try_from(source.origin().record())
                .map_err(|_| MappingError::InvalidOutput)?,
            at: source
                .timestamp()
                .map_or_else(String::new, irmind_app::IndexedTime::to_rfc3339),
            event: "SyntheticLogin".into(),
            text: format!(
                "frontend actor={} namespace={namespace}",
                text(source, "actor")?
            ),
            entities: vec![],
            relations: vec![],
        },
        time: source.timestamp(),
        source_offset: source.origin().offset(),
    })
}

fn ingest_sources(
    store: &LocalStore,
    engine: &Engine<'_>,
    catalog: &MappingCatalog,
    case: &CaseId,
    root: &Path,
) {
    for (index, (cluster, namespace)) in [("a", "production"), ("b", "production"), ("a", "test")]
        .into_iter()
        .enumerate()
    {
        let context = named_context(cluster);
        let parser = catalog
            .decoder_selection("parser-json", "json-source-v1")
            .unwrap()
            .with_cluster_context(&context)
            .unwrap();
        let large = LargeCaseUseCases {
            engine,
            store,
            parser: parser.as_ref(),
        };
        ingest_cluster(
            &large,
            root,
            case,
            &format!("source-{index}.json"),
            &context,
            u8::try_from(index).unwrap(),
            namespace,
        );
    }
}

fn verify_and_export(
    store: &LocalStore,
    engine: &Engine<'_>,
    catalog: &MappingCatalog,
    case: &CaseId,
    root: &Path,
) {
    engine.verify(case).unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine,
            store,
            parser: &parser
        }
        .verify_parquet_rebuild(case, root, &CancellationToken::new())
        .unwrap(),
        3
    );
    engine.seal(case).unwrap();
    let target = root.join("clusters.irmind");
    let key =
        irmind_app::export_case(engine, store, case, &target, &CancellationToken::new()).unwrap();
    LocalExportVerifier
        .verify_export_details(&target, Some(&key))
        .unwrap();
}
