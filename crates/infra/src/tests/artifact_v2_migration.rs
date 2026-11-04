#![allow(clippy::too_many_lines)]
use super::*;
mod rejections;
use irmind_app::{LargeCaseStore, LargeCaseUseCases};
use irmind_domain::{AuditEventKind, ParquetArtifact};

fn setup(root: &std::path::Path) -> (Arc<LocalStore>, Engine<'static>) {
    let store = Arc::new(LocalStore::open(root).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[43; 32]),
        actor: Actor::Analyst,
    });
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    (store, engine)
}
fn ingest(
    store: &LocalStore,
    engine: &Engine<'_>,
    id: &CaseId,
    root: &std::path::Path,
    copy: bool,
) {
    fs::write(root.join("events.json"), br#"{"Records":[{"eventTime":"2026-11-01T12:00:00.000001900Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.77"}]}"#).unwrap();
    LargeCaseUseCases {
        engine,
        store,
        parser: &JsonParser,
    }
    .ingest_local(id, root, "events.json", copy, &CancellationToken::new())
    .unwrap();
}
#[test]
fn explicit_migration_keeps_history_queries_rebuild_seal_and_v5_public_verification() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine
        .create_case("Explicit migration", "local only")
        .unwrap()
        .id;
    ingest(&store, &engine, &id, root.path(), true);
    let before = store.entries(&id).unwrap();
    let old = irmind_app::artifact_catalog(&before).unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    };
    assert_eq!(
        large
            .migrate_artifacts_v2(&id, None, &CancellationToken::new())
            .unwrap(),
        3
    );
    let after = store.entries(&id).unwrap();
    assert_eq!(
        before.iter().map(|e| e.hash).collect::<Vec<_>>(),
        after[..before.len()]
            .iter()
            .map(|e| e.hash)
            .collect::<Vec<_>>()
    );
    let catalog = irmind_app::artifact_catalog(&after).unwrap();
    assert_eq!(catalog.all.len(), 6);
    assert_eq!(catalog.active.len(), 3);
    assert!(
        catalog
            .active
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V2(_)))
    );
    for a in &old.all {
        store
            .verify_artifact(&id, a, &CancellationToken::new())
            .unwrap();
    }
    assert_eq!(
        large
            .verify_parquet_rebuild(&id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    assert!(
        !store
            .signed_parquet_artifacts(&id)
            .unwrap()
            .unwrap()
            .is_empty()
    );
    engine.verify(&id).unwrap();
    engine.seal(&id).unwrap();
    engine.verify(&id).unwrap();
    let path = root.path().join("mixed.irmind");
    let key = irmind_app::export_case_v4(
        &engine,
        store.as_ref(),
        &id,
        &path,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let result = irmind_app::ExportVerifier::verify_export_details(
        &crate::LocalExportVerifier,
        &path,
        Some(&key),
    )
    .unwrap();
    assert_eq!(result.format_version, 5);
    assert!(crate::seal::verify_export_expected(&path, Some(&"0".repeat(64))).is_err());
    assert_eq!(
        after.last().unwrap().kind,
        AuditEventKind::ParquetArtifactsMigrated
    );
    assert!(matches!(
        large.migrate_artifacts_v2(&id, None, &CancellationToken::new()),
        Err(AppError::Sealed)
    ));
}
#[test]
fn migration_failure_and_cancellation_leave_signed_catalog_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine
        .create_case("Unavailable source", "local only")
        .unwrap()
        .id;
    ingest(&store, &engine, &id, root.path(), false);
    let before = store.entries(&id).unwrap().last().unwrap().hash;
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    };
    assert!(
        large
            .migrate_artifacts_v2(&id, None, &CancellationToken::new())
            .is_err()
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        large.migrate_artifacts_v2(&id, Some(root.path()), &cancel),
        Err(AppError::Cancelled)
    ));
    assert_eq!(store.entries(&id).unwrap().last().unwrap().hash, before);
    large
        .migrate_artifacts_v2(&id, Some(root.path()), &CancellationToken::new())
        .unwrap();
}

#[test]
fn failed_atomic_batch_removes_published_replacements_and_recovers_unsigned_orphans() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine
        .create_case("Atomic replacement", "local only")
        .unwrap()
        .id;
    ingest(&store, &engine, &id, root.path(), true);
    let before = store.entries(&id).unwrap().last().unwrap().hash;
    let kind = AuditEventKind::ParquetArtifactsMigrated.as_str();
    store.conn().unwrap().execute_batch(&format!("CREATE TRIGGER refuse_migration BEFORE INSERT ON audit WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(ABORT, 'injected transaction failure'); END;")).unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    };
    assert!(
        large
            .migrate_artifacts_v2(&id, None, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(store.entries(&id).unwrap().last().unwrap().hash, before);
    assert!(
        irmind_app::artifact_catalog(&store.entries(&id).unwrap())
            .unwrap()
            .active
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V1(_)))
    );
    store
        .conn()
        .unwrap()
        .execute_batch("DROP TRIGGER refuse_migration")
        .unwrap();
    let orphan = store
        .parquet
        .case_dir(&id)
        .unwrap()
        .join("date=2026-11-01")
        .join(format!("migration-{}", "a".repeat(64)));
    fs::create_dir_all(&orphan).unwrap();
    fs::write(orphan.join("events.parquet"), b"orphan").unwrap();
    assert_eq!(store.clean_orphan_spools(&id).unwrap(), 1);
    assert!(!orphan.exists());
    large
        .migrate_artifacts_v2(&id, None, &CancellationToken::new())
        .unwrap();
    assert_eq!(store.clean_orphan_spools(&id).unwrap(), 0);
    large
        .verify_parquet(&id, &CancellationToken::new())
        .unwrap();
}

#[test]
fn legacy_copied_case_can_explicitly_upgrade_after_its_compatible_parquet_conversion() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let signer = LocalSigner {
        key: SigningKey::from_bytes(&[43; 32]),
        actor: Actor::Analyst,
    };
    let id = engine
        .create_case("Legacy precision upgrade", "local only")
        .unwrap()
        .id;
    ingest_historical_fixture(store.as_ref(),&signer,&id,br#"{"eventTime":"2026-11-01T00:00:00.000001900Z","eventName":"Login","sourceIPAddress":"203.0.113.77"}"#,"old.json");
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    };
    large
        .migrate_legacy_open(&id, &CancellationToken::new())
        .unwrap();
    large
        .migrate_artifacts_v2(&id, None, &CancellationToken::new())
        .unwrap();
    large
        .verify_parquet_rebuild(&id, root.path(), &CancellationToken::new())
        .unwrap();
    assert!(
        store
            .text_search(&id, "203.0.113.77", 5)
            .unwrap()
            .contains("Login")
    );
    engine.verify(&id).unwrap();
}

#[test]
fn v5_checks_original_frames_and_rejects_truncation_and_version_confusion() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine.create_case("V5 originals", "local only").unwrap().id;
    ingest(&store, &engine, &id, root.path(), false);
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    }
    .migrate_artifacts_v2(&id, Some(root.path()), &CancellationToken::new())
    .unwrap();
    engine.seal(&id).unwrap();
    let archive = root.path().join("with-originals.irmind");
    let key = irmind_app::export_case_v4(
        &engine,
        store.as_ref(),
        &id,
        &archive,
        Some(root.path()),
        true,
        &CancellationToken::new(),
    )
    .unwrap();
    let result = irmind_app::ExportVerifier::verify_export_details(
        &LocalExportVerifier,
        &archive,
        Some(&key),
    )
    .unwrap();
    assert_eq!(result.format_version, 5);
    assert_eq!(result.source_bytes_verified, 1);
    let bytes = fs::read(&archive).unwrap();
    assert!(bytes.starts_with(b"IRMIND-EXPORT-V5\0"));
    let original = fs::read(root.path().join("events.json")).unwrap();
    let offset = bytes
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    let mut changed = bytes.clone();
    changed[offset] ^= 1;
    fs::write(&archive, changed).unwrap();
    assert!(matches!(
        verify_export(&archive),
        Err(AppError::EvidenceMismatch(_))
    ));
    for cut in [16, bytes.len() - 1] {
        fs::write(&archive, &bytes[..cut]).unwrap();
        assert!(verify_export(&archive).is_err());
    }
    let mut confused = bytes;
    confused[b"IRMIND-EXPORT-V".len()] = b'4';
    fs::write(&archive, confused).unwrap();
    assert!(verify_export(&archive).is_err());
}

#[test]
fn independently_framed_v5_fuzz_seed_verifies_without_a_keystore() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("seed.irmind");
    fs::write(
        &path,
        include_bytes!("../../../../fuzz/seeds/export/valid-v5.irmind"),
    )
    .unwrap();
    let result =
        irmind_app::ExportVerifier::verify_export_details(&LocalExportVerifier, &path, None)
            .unwrap();
    assert_eq!(result.format_version, 5);
    assert_eq!(result.entries, 2);
}
