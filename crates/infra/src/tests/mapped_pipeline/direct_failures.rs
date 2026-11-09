use super::*;
use irmind_app::{LargeCaseStore, MappedIngestRequest, RejectedSource};

#[test]
fn seventeen_excluded_sources_abort_without_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let case = engine.create_case("Bounded retries", "local only").unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let names = (0..18)
        .map(|i| {
            let name = format!("bad-{i:02}.json");
            fs::write(root.path().join(&name), b"{broken").unwrap();
            name
        })
        .collect::<Vec<_>>();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    assert!(
        large
            .ingest_local_batch(
                &case.id,
                root.path(),
                &names,
                false,
                &CancellationToken::new()
            )
            .is_err()
    );
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter_map(|e| RejectedSource::from_audit(e).unwrap())
            .count(),
        17
    );
    assert!(
        irmind_app::artifact_catalog(&entries)
            .unwrap()
            .all
            .is_empty()
    );
    assert!(artifact_files(&store.parquet.case_dir(&case.id).unwrap()).is_empty());
    engine.verify(&case.id).unwrap();
}

#[test]
fn dropping_uncommitted_publication_removes_outputs_and_private_copies() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let case = engine
        .create_case("Publication rollback", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    fs::write(
        root.path().join("input.json"),
        br#"{"eventTime":"2026-11-01T00:00:00Z","sourceIPAddress":"203.0.113.77"}"#,
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let mut prepared = store
        .prepare_mapped_ingest(
            MappedIngestRequest {
                case_id: &case.id,
                source_root: root.path(),
                relative_paths: &["input.json".into()],
                copy_original: true,
                parser: &parser,
                committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
                limits: irmind_app::PartitionLimits::default(),
            },
            &cancel,
        )
        .unwrap()
        .unwrap();
    assert!(
        store
            .entries(&case.id)
            .unwrap()
            .iter()
            .all(|e| e.kind != AuditEventKind::SourceManifestV2)
    );
    prepared.publish(&cancel).unwrap();
    assert!(!artifact_files(&store.parquet.case_dir(&case.id).unwrap()).is_empty());
    drop(prepared);
    assert!(artifact_files(&store.parquet.case_dir(&case.id).unwrap()).is_empty());
    assert_eq!(
        fs::read_dir(store.parquet.case_dir(&case.id).unwrap().join("originals"))
            .unwrap()
            .count(),
        0
    );
    engine.verify(&case.id).unwrap();
}

#[test]
fn cancelled_group_has_no_signed_sources_or_leftover_files() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let case = engine
        .create_case("Cancelled direct group", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let token = CancellationToken::new();
    token.cancel();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    assert!(matches!(
        large.ingest_local_batch(
            &case.id,
            root.path(),
            &["missing.json".into()],
            false,
            &token
        ),
        Err(AppError::Cancelled)
    ));
    assert!(artifact_files(&store.parquet.case_dir(&case.id).unwrap()).is_empty());
    assert_eq!(store.entries(&case.id).unwrap().len(), 1);
}

struct FailingSign(Arc<dyn irmind_app::Signer>);
impl irmind_app::Signer for FailingSign {
    fn actor(&self) -> Actor {
        self.0.actor()
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, AppError> {
        Err(AppError::Signature("synthetic signing failure".into()))
    }
}

#[test]
fn signing_error_rolls_back_publication_without_excluding_a_valid_source() {
    let root = tempfile::tempdir().unwrap();
    let (store, mut engine, catalog) = fixture(root.path());
    let case = engine
        .create_case("Signing rollback", "local only")
        .unwrap();
    engine.signer = Arc::new(FailingSign(engine.signer.clone()));
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    fs::write(
        root.path().join("input.json"),
        br#"{"eventTime":"2026-11-01T00:00:00Z","sourceIPAddress":"203.0.113.77"}"#,
    )
    .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    assert!(matches!(
        large.ingest_local_batch(
            &case.id,
            root.path(),
            &["input.json".into()],
            true,
            &CancellationToken::new()
        ),
        Err(AppError::Signature(_))
    ));
    assert_eq!(store.entries(&case.id).unwrap().len(), 1);
    assert!(artifact_files(&store.parquet.case_dir(&case.id).unwrap()).is_empty());
}

fn artifact_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(artifact_files(&path));
        } else if path
            .extension()
            .is_some_and(|e| e == "parquet" || e == "tmp")
        {
            found.push(path);
        }
    }
    found
}
