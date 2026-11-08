//! Public-key-only V6 authentication includes every retained layout parent.
use super::*;
use irmind_app::{LargeCaseStore, LargeCaseUseCases};
use irmind_domain::AuditEventKind;
use irmind_domain::{
    ArtifactPipelineV1, EvidenceHash, MappingBindingV1, MappingCountsV1, MappingInputRefV1,
    MappingProfileV1, MappingRouteV1, MappingRunV1, ParquetArtifact, ParquetArtifactV3,
    ParserSelectionMode, SourceFormatIdentityV1, SourceManifestV2, SourceRecordSetV1,
    SourceReferenceV1,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder as Reader;
use std::fs::File;

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
    let store = Arc::new(LocalStore::open_common(root).unwrap());
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
            Arc::new(JsonParser),
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
    let prepared = store
        .prepare_local_batch(
            irmind_app::LocalBatchRequest {
                case_id: id,
                source_root: root,
                relative_paths: &[name.into()],
                copy_original: true,
                parser: &JsonParser,
                committed_artifacts: &[],
                limits: irmind_app::PartitionLimits::default(),
            },
            &CancellationToken::new(),
        )
        .unwrap()
        .pop()
        .unwrap();
    let manifest = SourceManifestV2 {
        source: prepared.manifest,
        parser_id: "parser-json".into(),
        parser_version: "json-stream-v3".into(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: vec![],
    };
    let input = SourceRecordSetV1::from_manifest(
        &manifest,
        SourceReferenceV1::file(name).unwrap(),
        vec![SourceFormatIdentityV1::try_new("json", "source-json-v1").unwrap()],
        prepared.records as u64,
        EvidenceHash::from_bytes([9; 32]),
    )
    .unwrap();
    let profile =
        MappingProfileV1::try_new(vec![MappingInputRefV1::from_set(&input).unwrap()], vec![])
            .unwrap();
    let binding = MappingBindingV1::new(
        MappingInputRefV1::from_set(&input).unwrap(),
        profile.identity().unwrap(),
        profile.catalog_identity(),
        input.decoder().clone(),
        None,
    );
    append(
        store,
        signer,
        id,
        AuditEventKind::SourceManifestV2,
        manifest.encode().unwrap(),
    );
    append(
        store,
        signer,
        id,
        AuditEventKind::SourceRecordSetV1,
        input.encode().unwrap(),
    );
    append(
        store,
        signer,
        id,
        AuditEventKind::MappingProfileV1,
        profile.encode().unwrap(),
    );
    let mut artifacts = Vec::new();
    for artifact in prepared.artifacts {
        let core = artifact.precise_metadata().unwrap().clone();
        let reader = Reader::try_new(
            File::open(store.parquet.case_dir(id).unwrap().join(&core.path)).unwrap(),
        )
        .unwrap();
        let count = u64::try_from(reader.metadata().file_metadata().num_rows()).unwrap();
        let mapped = ParquetArtifactV3::try_new(
            core,
            ArtifactPipelineV1::mapped(vec![binding.clone()], count).unwrap(),
        )
        .unwrap();
        append(
            store,
            signer,
            id,
            AuditEventKind::ParquetArtifactV3,
            mapped.encode().unwrap(),
        );
        artifacts.push(mapped);
    }
    let receipt = MappingRunV1::between(
        &profile,
        vec![
            MappingRouteV1::try_new(
                input.source().clone(),
                None,
                MappingCountsV1::try_new(input.records(), input.records(), 0, 0).unwrap(),
            )
            .unwrap(),
        ],
        &artifacts,
    )
    .unwrap();
    append(
        store,
        signer,
        id,
        AuditEventKind::MappingRunV1,
        receipt.encode().unwrap(),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn v6_export_authenticates_retained_parents_receipts_schema_and_public_key() {
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
        parser: &JsonParser,
    };
    assert_eq!(large.compact_case(&case.id, &cancel).unwrap(), 3);
    let catalog = irmind_app::artifact_catalog(&store.entries(&case.id).unwrap()).unwrap();
    assert_eq!((catalog.all.len(), catalog.active.len()), (9, 3));
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let package = root.path().join("mapped.irmind");
    let expected = irmind_app::export_case_v4(
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
    assert_eq!(details.format_version, 6);
    assert_eq!(details.source_manifests, 2);
    assert!(
        crate::LocalExportVerifier
            .verify_export_details(&package, Some(&"0".repeat(64)))
            .is_err()
    );
    let mut bytes = fs::read(&package).unwrap();
    assert!(bytes.starts_with(b"IRMIND-EXPORT-V6\0"));
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
        irmind_app::export_case_v4(
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
