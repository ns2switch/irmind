//! Public-key-only export authentication includes every retained layout parent.
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
fn v11_export_authenticates_retained_parents_receipts_schema_and_public_key() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, signer) = setup(root.path());
    let case = engine
        .create_case("Mapped synthetic export", "local only")
        .unwrap();
    let initial = engine.source_query_allocation(&case.id).unwrap();
    assert_eq!(
        initial,
        (
            0,
            irmind_app::source_queries::SourceQueryAllocationV1::default()
        )
    );
    let mut budget: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/budget.json"
    ))
    .unwrap();
    budget["case_id"] = case.id.as_str().into();
    let payload = irmind_app::source_queries::canonical_query_json(&budget).unwrap();
    append(
        &store,
        &signer,
        &case.id,
        AuditEventKind::SourceQueryBudgetV1,
        String::from_utf8(payload).unwrap(),
    );
    let revised = engine.source_query_allocation(&case.id).unwrap();
    assert_eq!((revised.0, revised.1.scan_bytes), (1, Some(32 << 20)));
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
    assert_eq!(details.format_version, 11);
    assert_eq!(details.source_manifests, 2);
    assert!(
        crate::LocalExportVerifier
            .verify_export_details(&package, Some(&"0".repeat(64)))
            .is_err()
    );
    let mut bytes = fs::read(&package).unwrap();
    assert!(bytes.starts_with(b"IRMIND-EXPORT-V11\0"));
    seed::verify_required_tail(&bytes, root.path());
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

#[test]
fn source_query_adoption_persists_only_valid_canonical_scope() {
    let root = tempfile::tempdir().unwrap();
    let (store, mut engine, signer) = setup(root.path());
    let vector = include_bytes!(
        "../../../../docs/development/source-query-format-vectors/configuration-adoption.json"
    );
    let mut wrong: serde_json::Value = serde_json::from_slice(vector).unwrap();
    wrong["policy"]["regions"] = serde_json::json!(["us-east-1"]);
    assert!(
        engine
            .adopt_source_query_configuration(
                &irmind_app::source_queries::canonical_query_json(&wrong).unwrap(),
            )
            .is_err()
    );
    engine.mode = ExecutionMode::Unattended;
    assert!(engine.adopt_source_query_configuration(vector).is_err());
    assert!(store.global_operations().unwrap().is_empty());
    engine.mode = ExecutionMode::Attended;
    let adoption = engine.adopt_source_query_configuration(vector).unwrap();
    assert_eq!(adoption.actor, Actor::Analyst);
    assert_eq!(adoption.public_key, signer.public_key());
    assert_eq!(adoption.hash, store.global_operations().unwrap()[0].hash);
    engine.verify_global_operations().unwrap();
}

mod seed;

#[test]
fn source_query_recovery_requires_a_signed_expired_analytics_observation() {
    use irmind_app::source_queries::{SourceQueryJournal, SourceQueryRecoveryV1};
    let config: SignedOperation = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/signed-recovery-configuration.json"
    )).unwrap();
    let mut chain: Vec<SignedEntry> = serde_json::from_slice(include_bytes!(
        "../../../testkit/fixtures/contracts/signed-recovery-chain-case-v7.json"
    ))
    .unwrap();
    let record =
        include_bytes!("../../../../docs/development/source-query-format-vectors/recovery.json");
    assert_eq!(chain[7].payload.as_bytes(), record);
    let vector = hex::decode(
        include_str!(
            "../../../../docs/development/source-query-format-vectors/recovery-preimage.hex"
        )
        .trim(),
    )
    .unwrap();
    assert_eq!(
        SourceQueryRecoveryV1::decode(record)
            .unwrap()
            .content_id()
            .unwrap(),
        hex(&sha256(&vector))
    );
    let signer = LocalSigner {
        key: SigningKey::from_bytes(&[77; 32]),
        actor: Actor::Analyst,
    };
    let verifier = LocalVerifier::from_signer(&signer)
        .with_trusted_key(&chain[6].actor, &chain[6].public_key)
        .unwrap();
    let cancel = CancellationToken::new();
    let operations = [config];
    let prior = SourceQueryJournal::replay(&chain[..7], &operations, &verifier, &cancel).unwrap();
    let recovered = SourceQueryJournal::replay(&chain, &operations, &verifier, &cancel).unwrap();
    assert_eq!(recovered.held(), prior.held());
    assert_eq!(recovered.used(), prior.used());
    assert_eq!(recovered.captures().len(), 0);
    let recovery = chain.last_mut().unwrap();
    recovery.at -= 1;
    recovery.hash = sha256(&recovery.canonical());
    recovery.sig = signer.sign(&recovery.hash).unwrap();
    assert!(SourceQueryJournal::replay(&chain, &operations, &verifier, &cancel).is_err());
}

#[test]
fn source_query_reservation_and_submit_intent_survive_reopen_as_one_batch() {
    use irmind_app::CaseMutation;
    let root = tempfile::tempdir().unwrap();
    let chain: Vec<SignedEntry> = serde_json::from_slice(include_bytes!(
        "../../../testkit/fixtures/contracts/signed-record-chain-case-v7.json"
    ))
    .unwrap();
    let first = &chain[0];
    let id = CaseId::parse(&first.case_id).unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&first.payload).unwrap();
    let store = LocalStore::open_mapped(root.path(), mapping_catalog()).unwrap();
    let lock = store.lock_case(&id).unwrap();
    store
        .transact(
            first,
            CaseMutation::Create(Case {
                id: id.clone(),
                title: metadata["title"].as_str().unwrap().into(),
                severity: Severity::Medium,
                scope: metadata["scope"].as_str().unwrap().into(),
                sealed: false,
            }),
        )
        .unwrap();
    store.append_batch(&chain[1..4]).unwrap();
    let mut corrupt = chain[5].clone();
    corrupt.seq += 1;
    assert!(store.append_batch(&[chain[4].clone(), corrupt]).is_err());
    assert_eq!(store.last_entry(&id).unwrap().unwrap().hash, chain[3].hash);
    store.append_batch(&chain[4..6]).unwrap();
    drop(lock);
    drop(store);
    let reopened = LocalStore::open_mapped(root.path(), mapping_catalog()).unwrap();
    let durable = reopened.entries(&id).unwrap();
    assert_eq!(
        durable.iter().map(|entry| entry.hash).collect::<Vec<_>>(),
        chain[..6]
            .iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>()
    );
}

#[test]
fn source_query_broker_requires_the_pinned_analyst_and_agent_proofs() {
    use irmind_app::source_queries::{
        SignedSourceQueryAdmission, SourceQueryAllocationV1, SourceQueryAuthority,
        SourceQueryBroker,
    };
    use irmind_domain::{AgentId, CaseScope};
    let chain: Vec<SignedEntry> = serde_json::from_slice(include_bytes!(
        "../../../testkit/fixtures/contracts/signed-record-chain-case-v7.json"
    ))
    .unwrap();
    let principal = AgentId::parse("main").unwrap();
    let (plan, approval, reservation) = (&chain[2], &chain[3], &chain[4]);
    let operation: irmind_app::SignedOperation = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/source-query-format-vectors/signed-configuration.json"
    ))
    .unwrap();
    let verifier = LocalVerifier {
        trusted: std::collections::BTreeMap::new(),
    }
    .with_trusted_key(&Actor::Analyst, &approval.public_key)
    .unwrap()
    .with_trusted_key(&Actor::Agent(principal.clone()), &plan.public_key)
    .unwrap();
    let scope = CaseScope::parse("v1;sources=aws-lab;accounts=111122223333;hosts=;from=2026-11-01T00:00:00Z;to=2026-12-01T00:00:00Z").unwrap();
    let allocation = SourceQueryAllocationV1 {
        enabled: true,
        analytics_allowed: false,
        scan_bytes: Some(32 << 20),
        retained_rows: 1_000_000,
        retained_bytes: 1_000_000_000,
    };
    let mut broker = SourceQueryBroker::new(
        CaseId::parse(&plan.case_id).unwrap(),
        allocation,
        allocation,
    )
    .unwrap();
    broker.change_allocation(1, allocation).unwrap();
    let authority = SourceQueryAuthority {
        principal: &principal,
        case_scope: &scope,
        organization_scope: &scope,
        requires_policy_approval: false,
        verifier: &verifier,
    };
    let candidate = SignedSourceQueryAdmission {
        plan,
        approval: Some(approval),
        reservation,
        intent: &chain[5],
        configuration: &operation,
    };
    let mut tampered = approval.clone();
    tampered.sig[0] ^= 1;
    let mut wrong_configuration = operation.clone();
    wrong_configuration.operation.push('0');
    for invalid in [
        SignedSourceQueryAdmission {
            approval: Some(&tampered),
            ..candidate
        },
        SignedSourceQueryAdmission {
            configuration: &wrong_configuration,
            ..candidate
        },
        SignedSourceQueryAdmission {
            intent: &chain[6],
            ..candidate
        },
    ] {
        assert!(broker.reserve_authenticated(invalid, authority).is_err());
        assert_eq!(broker.held().retained_rows, 0);
    }
    let hold = broker.reserve_authenticated(candidate, authority).unwrap();
    assert_eq!(hold.resources().scan_bytes, 11 << 20);

    check_capture_spools_require_durable_intent(&broker, hold.id(), &chain);
    check_signed_settlement(&mut broker, &chain, &principal, &verifier);
}

fn check_capture_spools_require_durable_intent(
    broker: &irmind_app::source_queries::SourceQueryBroker,
    reservation: &str,
    chain: &[SignedEntry],
) {
    let root = tempfile::tempdir().unwrap();
    let store = LocalStore::open(root.path()).unwrap();
    let id = CaseId::parse(&chain[0].case_id).unwrap();
    let _lock = store.lock_case(&id).unwrap();
    let first = &chain[0];
    let metadata: serde_json::Value = serde_json::from_str(&first.payload).unwrap();
    store
        .transact(
            first,
            irmind_app::CaseMutation::Create(Case {
                id: id.clone(),
                title: metadata["title"].as_str().unwrap().into(),
                severity: Severity::Medium,
                scope: metadata["scope"].as_str().unwrap().into(),
                sealed: false,
            }),
        )
        .unwrap();
    store.append_batch(&chain[1..4]).unwrap();
    let cancel = CancellationToken::new();
    let spool_dir = store.parquet.owned_case_path(&id).join("spool");
    assert!(
        broker
            .prepare_capture_spools(reservation, &store, &store, &cancel)
            .is_err()
    );
    assert!(!spool_dir.exists());
    store.append_batch(&chain[4..6]).unwrap();
    let (writer, output) = broker
        .prepare_capture_spools(reservation, &store, &store, &cancel)
        .unwrap();
    assert_eq!(fs::read_dir(&spool_dir).unwrap().count(), 2);
    drop((writer, output));
    assert_eq!(fs::read_dir(&spool_dir).unwrap().count(), 0);
}

fn check_signed_settlement(
    broker: &mut irmind_app::source_queries::SourceQueryBroker,
    chain: &[SignedEntry],
    principal: &irmind_domain::AgentId,
    verifier: &LocalVerifier,
) {
    let expected_hold = broker.held();
    let intent = &chain[5];
    let execution = &chain[6];
    let result = &chain[7];
    let settlement = &chain[8];
    let bytes = hex::decode(
        include_str!("../../../../docs/development/source-query-format-vectors/capture.hex").trim(),
    )
    .unwrap();
    let capture = irmind_app::source_queries::verify_query_capture(
        bytes.as_slice(),
        &CancellationToken::new(),
    )
    .unwrap();
    let receipts = irmind_app::source_queries::SignedSourceQuerySettlement {
        observations: &[intent, execution],
        result: Some((result, &capture)),
        settlement,
    };
    assert!(
        broker
            .settle_authenticated(
                irmind_app::source_queries::SignedSourceQuerySettlement {
                    observations: &[execution],
                    ..receipts
                },
                principal,
                verifier
            )
            .is_err()
    );
    assert!(
        broker
            .settle_authenticated(
                irmind_app::source_queries::SignedSourceQuerySettlement {
                    result: None,
                    ..receipts
                },
                principal,
                verifier
            )
            .is_err()
    );
    assert_eq!(broker.held(), expected_hold);
    broker
        .settle_authenticated(receipts, principal, verifier)
        .unwrap();
    assert_eq!(broker.used().scan_bytes, 10 << 20);
    assert_eq!(broker.used().retained_bytes, 2391);
    assert!(
        broker
            .settle_authenticated(receipts, principal, verifier)
            .is_err()
    );
}
