use super::*;
use irmind_app::ExportVerifier;
use irmind_domain::{CommonEventFilter, EntityRole, EventCategory, EventOutcome, GraphQueryFilter};
#[test]
fn native_entra_exports_keep_outcomes_roles_and_signed_reconstruction() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic Entra exports", "local only")
        .unwrap();
    for (name, bytes) in [
        (
            "signin-resource.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/signin-resource.ndjson")
                .as_slice(),
        ),
        (
            "signin-table.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/signin-table.ndjson")
                .as_slice(),
        ),
        (
            "audit-resource.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/audit-resource.ndjson")
                .as_slice(),
        ),
        (
            "audit-table.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/audit-table.ndjson")
                .as_slice(),
        ),
    ] {
        fs::write(originals.join(name), bytes).unwrap();
        assert_eq!(
            ingest_with_context(&engine, store.as_ref(), &case.id, &originals, name, None),
            1
        );
    }
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 4);
    for (category, outcome, role) in [
        (
            EventCategory::Authentication,
            EventOutcome::Failure,
            EntityRole::Source,
        ),
        (EventCategory::Iam, EventOutcome::Success, EntityRole::Actor),
        (
            EventCategory::Iam,
            EventOutcome::Success,
            EntityRole::Target,
        ),
    ] {
        let filter = GraphQueryFilter::default().with_common(CommonEventFilter {
            category: Some(category),
            outcome: Some(outcome),
            role: Some(role),
            ..Default::default()
        });
        assert_eq!(
            store
                .timeline_filtered(&case.id, &filter, 10)
                .unwrap()
                .len(),
            2
        );
    }
    verify_custody(
        &engine,
        store.as_ref(),
        &case.id,
        &originals,
        &root.path().join("synthetic.irmind"),
    );
}
fn verify_custody(
    engine: &Engine<'_>,
    store: &LocalStore,
    id: &irmind_domain::CaseId,
    originals: &std::path::Path,
    path: &std::path::Path,
) {
    let parser = current_sources::parser("parser-entra");
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
