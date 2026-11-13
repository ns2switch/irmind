#![forbid(unsafe_code)]
#![cfg(all(feature = "parser-kubernetes", feature = "parser-falco"))]
#![allow(clippy::unwrap_used)]
#[path = "kubernetes_ingest/benchmark.rs"]
mod benchmark;
#[path = "support/current_sources.rs"]
mod current_sources;
#[cfg(feature = "parser-entra")]
#[path = "kubernetes_ingest/entra.rs"]
mod entra;
#[path = "kubernetes_ingest/managed.rs"]
mod managed;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, Signer, modules::ParserSelectionRequest,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, SourceManifestV2};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
use std::{collections::BTreeMap, fs, sync::Arc};
struct SyntheticSigner(SigningKey);
impl Signer for SyntheticSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.0.sign(bytes).to_bytes().to_vec())
    }
}
fn engine(store: &Arc<LocalStore>) -> Engine<'static> {
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[45; 32])));
    Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
}
fn context() -> irmind_domain::SourceClusterContext {
    irmind_app::command_cluster_context(Some("kubernetes:urn:k8s:synthetic"))
        .unwrap()
        .unwrap()
}
fn ingest(
    engine: &Engine<'_>,
    store: &LocalStore,
    case: &irmind_domain::CaseId,
    root: &std::path::Path,
    file: &str,
) -> u64 {
    ingest_with_context(engine, store, case, root, file, Some(&context()))
}
fn ingest_with_context(
    engine: &Engine<'_>,
    store: &LocalStore,
    case: &irmind_domain::CaseId,
    root: &std::path::Path,
    file: &str,
    cluster_context: Option<&irmind_domain::SourceClusterContext>,
) -> u64 {
    use std::io::Read as _;
    let mut sample = Vec::new();
    std::io::Read::take(fs::File::open(root.join(file)).unwrap(), 65536)
        .read_to_end(&mut sample)
        .unwrap();
    let catalog = current_sources::catalog();
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: file,
            sample: &sample,
            parser_override: None,
            forced: false,
            time_context: None,
            cluster_context,
        })
        .unwrap();
    LargeCaseUseCases {
        engine,
        store,
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        case,
        root,
        &[file.into()],
        false,
        &BTreeMap::from([(file.into(), selected.selection)]),
        &CancellationToken::new(),
    )
    .unwrap();
    let entries = store.entries(case).unwrap();
    let manifest = entries
        .iter()
        .rev()
        .find(|e| e.kind == AuditEventKind::SourceManifestV2)
        .map(|e| SourceManifestV2::decode(&e.payload).unwrap())
        .unwrap();
    assert_eq!(manifest.rejected_records, 0);
    entries
        .iter()
        .rev()
        .find(|e| e.kind == AuditEventKind::SourceRecordSetV1)
        .map(|e| {
            irmind_domain::SourceRecordSetV1::decode(&e.payload)
                .unwrap()
                .records()
        })
        .unwrap()
}
#[test]
fn native_and_falco_records_keep_cluster_roles_through_rebuild_seal_and_export() {
    use irmind_app::ExportVerifier;
    use irmind_domain::{CommonEventFilter, EventCategory, EventOutcome, GraphQueryFilter};
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic cluster evidence", "local evidence only")
        .unwrap();
    for (name, raw) in [
        (
            "audit.ndjson",
            include_bytes!("../../testkit/fixtures/parser-kubernetes/source/events.ndjson")
                .as_slice(),
        ),
        (
            "falco.ndjson",
            include_bytes!("../../testkit/fixtures/parser-falco/source/events.ndjson").as_slice(),
        ),
    ] {
        fs::write(originals.join(name), raw).unwrap();
        assert_eq!(
            ingest(&engine, store.as_ref(), &case.id, &originals, name),
            2
        );
    }
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 4);
    let filter = GraphQueryFilter::default()
        .with_cluster("kubernetes:urn:k8s:synthetic")
        .unwrap()
        .with_common(CommonEventFilter {
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
    let search = store
        .text_search(&case.id, "never-project-this-body", 10)
        .unwrap();
    assert!(!search.contains("never-project-this-body"));
    engine.verify(&case.id).unwrap();
    let parser = current_sources::parser("parser-kubernetes");
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    }
    .verify_parquet_rebuild(&case.id, &originals, &CancellationToken::new())
    .unwrap();
    engine.seal(&case.id).unwrap();
    let target = root.path().join("synthetic.irmind");
    let key = irmind_app::export_case(
        &engine,
        store.as_ref(),
        &case.id,
        &target,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(
        irmind_infra::LocalExportVerifier
            .verify_export_details(&target, Some(&key))
            .unwrap()
            .format_version,
        7
    );
}

#[cfg(feature = "parser-gcp-audit")]
#[test]
fn cloud_and_gke_sources_keep_separate_context_and_reconstruct_the_same_signed_graph() {
    use irmind_domain::{CommonEventFilter, EventCategory, EventOutcome, GraphQueryFilter};
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic GCP audit", "local only")
        .unwrap();
    let context = irmind_app::command_cluster_context(Some(
        "gke:projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
    ))
    .unwrap()
    .unwrap();
    for (name, bytes, context, count) in [
        (
            "cloud.ndjson",
            include_bytes!("../../testkit/fixtures/parser-gcp-audit/source/events.ndjson")
                .as_slice(),
            None,
            2,
        ),
        (
            "gke.ndjson",
            include_bytes!("../../testkit/fixtures/parser-gcp-audit/source/gke.ndjson").as_slice(),
            Some(&context),
            1,
        ),
    ] {
        fs::write(originals.join(name), bytes).unwrap();
        assert_eq!(
            ingest_with_context(&engine, store.as_ref(), &case.id, &originals, name, context),
            count
        );
    }
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 3);
    let filter = GraphQueryFilter::default().with_common(CommonEventFilter {
        category: Some(EventCategory::Iam),
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
    let filter = GraphQueryFilter::default()
        .with_cluster(
            "gke:projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
        )
        .unwrap();
    assert_eq!(
        store
            .timeline_filtered(&case.id, &filter, 10)
            .unwrap()
            .len(),
        1
    );
    verify_gcp_custody(
        &engine,
        store.as_ref(),
        &case.id,
        &originals,
        &root.path().join("synthetic.irmind"),
    );
}

#[cfg(feature = "parser-gcp-audit")]
fn verify_gcp_custody(
    engine: &Engine<'_>,
    store: &LocalStore,
    id: &irmind_domain::CaseId,
    originals: &std::path::Path,
    path: &std::path::Path,
) {
    use irmind_app::ExportVerifier;
    let parser = current_sources::parser("parser-gcp-audit");
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
