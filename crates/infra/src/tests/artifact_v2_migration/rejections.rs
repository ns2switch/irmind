use super::*;
use irmind_app::{ArtifactMigrationRequest, PreparedArtifactMigration};
fn draft(entries: &[SignedEntry], prepared: &dyn PreparedArtifactMigration) -> Vec<SignedEntry> {
    let mut all = entries.to_vec();
    for artifact in prepared.artifacts() {
        let mut entry = all.last().unwrap().clone();
        entry.seq += 1;
        entry.kind = AuditEventKind::ParquetArtifactV2;
        entry.evidence = None;
        entry.payload = artifact.encode().unwrap();
        all.push(entry);
    }
    let mut entry = all.last().unwrap().clone();
    entry.seq += 1;
    entry.actor = Actor::Analyst;
    entry.kind = AuditEventKind::ParquetArtifactsMigrated;
    entry.payload = prepared.record().encode().unwrap();
    all.push(entry);
    all
}
#[test]
fn replacement_catalog_requires_complete_analyst_bound_batch_and_links() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine
        .create_case("Migration closure", "local only")
        .unwrap()
        .id;
    ingest(&store, &engine, &id, root.path(), true);
    let entries = store.entries(&id).unwrap();
    let cancel = CancellationToken::new();
    let prepared = store
        .prepare_artifact_migration(
            ArtifactMigrationRequest {
                case_id: &id,
                source_root: None,
                signed_entries: &entries,
                parser: &JsonParser,
                limits: irmind_app::PartitionLimits::default(),
            },
            &cancel,
        )
        .unwrap();
    let complete = draft(&entries, prepared.as_ref());
    assert!(irmind_app::artifact_catalog(&complete).is_ok());
    let mut missing_record = complete.clone();
    missing_record.pop();
    assert!(irmind_app::artifact_catalog(&missing_record).is_err());
    let mut agent = complete.clone();
    agent.last_mut().unwrap().actor =
        Actor::Agent(irmind_domain::AgentId::parse("worker").unwrap());
    assert!(irmind_app::artifact_catalog(&agent).is_err());
    let mut partial = complete.clone();
    partial.remove(entries.len());
    assert!(irmind_app::artifact_catalog(&partial).is_err());
    let mut unrelated = complete.clone();
    let artifact_entry = &mut unrelated[entries.len()];
    let mut artifact = irmind_domain::ParquetArtifactV2::decode(&artifact_entry.payload).unwrap();
    artifact.superseded_hashes = vec![irmind_domain::EvidenceHash::parse(&"7".repeat(64)).unwrap()];
    artifact_entry.payload = artifact.encode().unwrap();
    assert!(irmind_app::artifact_catalog(&unrelated).is_err());
    let mut replay = complete.clone();
    replay.extend_from_slice(&complete[entries.len()..]);
    assert!(irmind_app::artifact_catalog(&replay).is_err());
    let mut tampered = complete;
    let last = tampered.last_mut().unwrap();
    let mut record = irmind_domain::ParquetMigrationV1::decode(&last.payload).unwrap();
    record.previous.sha256 = irmind_domain::EvidenceHash::parse(&"8".repeat(64)).unwrap();
    last.payload = record.encode().unwrap();
    assert!(irmind_app::artifact_catalog(&tampered).is_err());
}
#[test]
fn published_uncommitted_files_are_removed_on_drop_and_old_catalog_stays_active() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine
        .create_case("Prepared replacement", "local only")
        .unwrap()
        .id;
    ingest(&store, &engine, &id, root.path(), true);
    let entries = store.entries(&id).unwrap();
    let cancel = CancellationToken::new();
    let mut prepared = store
        .prepare_artifact_migration(
            ArtifactMigrationRequest {
                case_id: &id,
                source_root: None,
                signed_entries: &entries,
                parser: &JsonParser,
                limits: irmind_app::PartitionLimits::default(),
            },
            &cancel,
        )
        .unwrap();
    let paths = prepared
        .artifacts()
        .iter()
        .map(|a| store.parquet.case_dir(&id).unwrap().join(&a.path))
        .collect::<Vec<_>>();
    prepared.publish(&cancel).unwrap();
    assert!(paths.iter().all(|p| p.exists()));
    assert!(
        store
            .signed_parquet_artifacts(&id)
            .unwrap()
            .unwrap()
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V1(_)))
    );
    drop(prepared);
    assert!(paths.iter().all(|p| !p.exists()));
    assert_eq!(store.clean_orphan_spools(&id).unwrap(), 0);
}
#[test]
fn changed_source_and_changed_historical_artifact_block_migration() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine
        .create_case("Verified originals", "local only")
        .unwrap()
        .id;
    ingest(&store, &engine, &id, root.path(), false);
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    };
    let head = store.last_entry(&id).unwrap().unwrap().hash;
    let original = fs::read(root.path().join("events.json")).unwrap();
    fs::write(root.path().join("events.json"), b"changed").unwrap();
    assert!(matches!(
        large.migrate_artifacts_v2(&id, Some(root.path()), &CancellationToken::new()),
        Err(AppError::EvidenceMismatch(_))
    ));
    fs::write(root.path().join("events.json"), original).unwrap();
    let artifact = irmind_app::artifact_catalog(&store.entries(&id).unwrap())
        .unwrap()
        .all
        .remove(0);
    fs::write(
        store.parquet.case_dir(&id).unwrap().join(artifact.path()),
        b"changed",
    )
    .unwrap();
    assert!(matches!(
        large.migrate_artifacts_v2(&id, Some(root.path()), &CancellationToken::new()),
        Err(AppError::EvidenceMismatch(_))
    ));
    assert_eq!(store.last_entry(&id).unwrap().unwrap().hash, head);
}

#[test]
fn migration_refuses_an_unapproved_change_to_non_time_query_scope() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine
        .create_case("Stable query meaning", "local only")
        .unwrap()
        .id;
    fs::write(root.path().join("scope.json"),br#"{"eventTime":"2026-11-01T12:00:00Z","eventName":"Test","provider":"aws","awsRegion":"eu-west-1"}"#).unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    };
    large
        .ingest_local(
            &id,
            root.path(),
            "scope.json",
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    let head = store.last_entry(&id).unwrap().unwrap().hash;
    assert!(matches!(
        large.migrate_artifacts_v2(&id, Some(root.path()), &CancellationToken::new()),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyArtifactMigrationMeaning
        ))
    ));
    assert_eq!(store.last_entry(&id).unwrap().unwrap().hash, head);
}
