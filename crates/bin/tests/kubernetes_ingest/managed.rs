use super::*;
use irmind_app::ExportVerifier;
use irmind_domain::{CommonEventFilter, EventCategory, EventOutcome, GraphQueryFilter};
#[test]
fn managed_sources_rebuild_from_original_transports_and_export_their_confirmed_clusters() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic managed Kubernetes", "local only")
        .unwrap();
    for (name, bytes, cluster) in [
        (
            "eks.json",
            include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/eks.json")
                .as_slice(),
            "eks:arn:aws:eks:us-east-1:111122223333:cluster/synthetic-cluster",
        ),
        (
            "aks.json",
            include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/aks.json")
                .as_slice(),
            "aks:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/synthetic/providers/Microsoft.ContainerService/managedClusters/synthetic-cluster",
        ),
    ] {
        fs::write(originals.join(name), bytes).unwrap();
        let context = irmind_app::command_cluster_context(Some(cluster))
            .unwrap()
            .unwrap();
        assert_eq!(
            ingest_with_context(
                &engine,
                store.as_ref(),
                &case.id,
                &originals,
                name,
                Some(&context)
            ),
            2
        );
        let filter = GraphQueryFilter::default().with_cluster(cluster).unwrap();
        assert_eq!(
            store
                .timeline_filtered(&case.id, &filter, 10)
                .unwrap()
                .len(),
            2
        );
        let filter = filter.with_common(CommonEventFilter {
            category: Some(EventCategory::Api),
            outcome: Some(EventOutcome::Failure),
            ..Default::default()
        });
        assert_eq!(
            store
                .timeline_filtered(&case.id, &filter, 10)
                .unwrap()
                .len(),
            1
        );
    }
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 4);
    assert!(
        !store
            .text_search(&case.id, "never-project-this-body", 10)
            .unwrap()
            .contains("never-project-this-body")
    );
    verify(
        &engine,
        store.as_ref(),
        &case.id,
        &originals,
        &root.path().join("synthetic.irmind"),
    );
}
fn verify(
    engine: &Engine<'_>,
    store: &LocalStore,
    id: &irmind_domain::CaseId,
    originals: &std::path::Path,
    path: &std::path::Path,
) {
    let parser = current_sources::parser("parser-kubernetes");
    LargeCaseUseCases {
        engine,
        store,
        parser: parser.as_ref(),
    }
    .verify_parquet_rebuild(id, originals, &CancellationToken::new())
    .unwrap();
    engine.verify(id).unwrap();
    engine.seal(id).unwrap();
    let key = irmind_app::export_case(engine, store, id, path, &CancellationToken::new()).unwrap();
    assert_eq!(
        irmind_infra::LocalExportVerifier
            .verify_export_details(path, Some(&key))
            .unwrap()
            .format_version,
        7
    );
}
