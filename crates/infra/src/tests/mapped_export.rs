//! Public-key-only V7 authentication includes every retained layout parent.
use super::*;
use irmind_app::{LargeCaseStore, LargeCaseUseCases};
use irmind_domain::AuditEventKind;
use irmind_domain::{ParquetArtifact, ParserSelectionMode, SourceManifestV2};

fn append(
    store: &LocalStore,
    signer: &LocalSigner,
    id: &CaseId,
    kind: AuditEventKind,
    payload: String,
) {
    let last = store.last_entry(id).unwrap().unwrap();
    let mut entry = SignedEntry {
        seq: last.seq + 1,
        case_id: id.as_str().into(),
        at: 0,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind,
        payload,
        evidence: None,
        prev: last.hash,
        hash: [0; 32],
        sig: vec![],
        public_key: signer.public_key(),
    };
    entry.hash = sha256(&entry.canonical());
    entry.sig = signer.sign(&entry.hash).unwrap();
    store.append(&entry).unwrap();
}
fn setup(root: &std::path::Path) -> (Arc<LocalStore>, Engine<'static>, Arc<LocalSigner>) {
    let store = Arc::new(LocalStore::open_mapped(root, mapping_catalog()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[88; 32]),
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
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    (store, engine, signer)
}

#[allow(clippy::too_many_lines)]
fn ingest(
    store: &LocalStore,
    signer: &LocalSigner,
    id: &CaseId,
    root: &std::path::Path,
    name: &str,
) {
    let parser = mapping_catalog()
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let cancel = CancellationToken::new();
    let mut prepared = store
        .prepare_mapped_ingest(
            irmind_app::MappedIngestRequest {
                case_id: id,
                source_root: root,
                relative_paths: &[name.into()],
                copy_original: true,
                parser: &parser,
                committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
                limits: irmind_app::PartitionLimits::default(),
            },
            &cancel,
        )
        .unwrap()
        .unwrap();
    let source = &prepared.metadata().sources[0];
    let manifest = SourceManifestV2 {
        source: source.manifest.clone(),
        parser_id: "parser-json".into(),
        parser_version: "json-source-v1".into(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        cluster_context: None,
        rejected_records: source.report.rejected,
        rejected_sample: source.report.samples.clone(),
    };
    let bound = prepared
        .metadata()
        .bind(std::slice::from_ref(&manifest))
        .unwrap();
    prepared.publish(&cancel).unwrap();
    append(
        store,
        signer,
        id,
        AuditEventKind::SourceManifestV2,
        manifest.encode().unwrap(),
    );
    for input in bound.inputs {
        append(
            store,
            signer,
            id,
            AuditEventKind::SourceRecordSetV1,
            input.encode().unwrap(),
        );
    }
    for snapshot in bound.snapshots {
        append(
            store,
            signer,
            id,
            AuditEventKind::MappingProfileV1,
            irmind_domain::MappingProfileRecordV1::Snapshot(snapshot)
                .encode()
                .unwrap(),
        );
    }
    append(
        store,
        signer,
        id,
        AuditEventKind::MappingProfileV1,
        bound.profile.encode().unwrap(),
    );
    for artifact in bound.artifacts {
        append(
            store,
            signer,
            id,
            AuditEventKind::ParquetArtifactV3,
            artifact.encode().unwrap(),
        );
    }
    append(
        store,
        signer,
        id,
        AuditEventKind::MappingRunV1,
        bound.receipt.encode().unwrap(),
    );
    prepared.retain_committed();
}

#[test]
#[allow(clippy::too_many_lines)]
fn v7_export_authenticates_retained_parents_receipts_schema_and_public_key() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, signer) = setup(root.path());
    let case = engine
        .create_case("Mapped synthetic export", "local only")
        .unwrap();
    for (name, second) in [("a.json", "01"), ("b.json", "02")] {
        fs::write(root.path().join(name), format!(
            "{{\"eventTime\":\"2026-11-01T00:00:{second}.000001Z\",\"eventName\":\"Login\",\"sourceIPAddress\":\"203.0.113.77\"}}"
        )).unwrap();
        ingest(&store, &signer, &case.id, root.path(), name);
    }
    let cancel = CancellationToken::new();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &json_source_parser(),
    };
    assert_eq!(
        large
            .compact_case_with_threshold(&case.id, 2, &cancel)
            .unwrap(),
        3
    );
    let catalog = irmind_app::artifact_catalog(&store.entries(&case.id).unwrap()).unwrap();
    assert_eq!((catalog.all.len(), catalog.active.len()), (9, 3));
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let package = root.path().join("mapped.irmind");
    let expected = irmind_app::export_case_with_originals(
        &engine,
        store.as_ref(),
        &case.id,
        &package,
        None,
        false,
        &cancel,
    )
    .unwrap();
    let details = crate::LocalExportVerifier
        .verify_export_details(&package, Some(&expected))
        .unwrap();
    assert_eq!(details.format_version, 7);
    assert_eq!(details.source_manifests, 2);
    assert!(
        crate::LocalExportVerifier
            .verify_export_details(&package, Some(&"0".repeat(64)))
            .is_err()
    );
    let mut bytes = fs::read(&package).unwrap();
    assert!(bytes.starts_with(b"IRMIND-EXPORT-V7\0"));
    bytes[..b"IRMIND-EXPORT-V5\0".len()].copy_from_slice(b"IRMIND-EXPORT-V5\0");
    let downgrade = root.path().join("downgrade.irmind");
    fs::write(&downgrade, bytes).unwrap();
    assert!(crate::verify_export(&downgrade).is_err());
    let parent = catalog
        .all
        .iter()
        .find(|a| {
            matches!(a,ParquetArtifact::V3(v)
        if matches!(v.pipeline().derivation(), irmind_domain::ArtifactDerivationV1::Mapped))
        })
        .unwrap();
    let path = store
        .parquet
        .case_dir(&case.id)
        .unwrap()
        .join(parent.path());
    fs::write(path, b"changed retained parent").unwrap();
    assert!(
        irmind_app::export_case_with_originals(
            &engine,
            store.as_ref(),
            &case.id,
            &root.path().join("changed.irmind"),
            None,
            false,
            &cancel
        )
        .is_err()
    );
}

fn mapping_catalog() -> Arc<irmind_app::source_mapping::MappingCatalog> {
    Arc::new(
        irmind_app::source_mapping::MappingCatalog::freeze(
            vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
            vec![Arc::new(
                irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    )
}

mod seed;
