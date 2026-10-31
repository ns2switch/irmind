use super::*;
use irmind_app::LargeCaseStore;

#[test]
fn signed_v2_manifest_counts_malformed_jsonl_without_dropping_later_records() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("inputs");
    fs::create_dir(&source_root).unwrap();
    let bytes = b"{\"eventTime\":\"2026-10-28T12:00:00Z\",\"eventName\":\"First\"}\n{broken\n{\"eventTime\":\"2026-10-28T12:01:00Z\",\"eventName\":\"Last\"}\n";
    fs::write(source_root.join("events.jsonl"), bytes).unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[71u8; 32]),
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
    let case = engine
        .create_case("synthetic malformed line", "local evidence only")
        .unwrap();
    let parquet = super::super::ParquetStore::open(root.path()).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &parquet,
        parser: &JsonParser,
    };
    let selection = std::collections::BTreeMap::from([(
        "events.jsonl".to_owned(),
        irmind_app::ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-stream-v2".into(),
            confidence: 90,
            mode: irmind_domain::ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: irmind_app::sha256(bytes),
        },
    )]);
    use_cases
        .ingest_local_batch_selected(
            &case.id,
            &source_root,
            &["events.jsonl".into()],
            false,
            &selection,
            &CancellationToken::new(),
        )
        .unwrap();
    let manifest = store
        .entries(&case.id)
        .unwrap()
        .into_iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .unwrap();
    let decoded = irmind_domain::SourceManifestV2::decode(&manifest.payload).unwrap();
    assert_eq!(decoded.rejected_records, 1);
    assert_eq!(decoded.rejected_sample.len(), 1);
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 2);
    assert!(engine.verify(&case.id).is_ok());
}

#[test]
#[allow(clippy::too_many_lines)]
fn signed_source_and_artifact_survive_reopen_and_detect_source_change() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("inputs");
    fs::create_dir(&source_root).unwrap();
    let path = source_root.join("cloudtrail.json");
    fs::write(&path, br#"{"Records":[{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.8"}]}"#).unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[71u8; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
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
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine
        .create_case("large case", "account 123456789012")
        .unwrap();
    let parquet = super::super::ParquetStore::open(root.path()).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &parquet,
        parser: parser.as_ref(),
    };
    let selection = std::collections::BTreeMap::from([(
        "cloudtrail.json".to_owned(),
        irmind_app::ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-stream-v2".into(),
            confidence: 90,
            mode: irmind_domain::ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: irmind_app::sha256(&fs::read(&path).unwrap()),
        },
    )]);
    let hash = use_cases
        .ingest_local_batch_selected(
            &case.id,
            &source_root,
            &["cloudtrail.json".into()],
            false,
            &selection,
            &CancellationToken::new(),
        )
        .unwrap()[0]
        .1
        .clone();
    assert!(
        store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|entry| { entry.kind == irmind_domain::AuditEventKind::SourceManifestV2 })
    );
    assert_eq!(
        use_cases
            .ingest_local(
                &case.id,
                &source_root,
                "cloudtrail.json",
                false,
                &CancellationToken::new(),
            )
            .unwrap(),
        hash
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 5);
    let source_report = use_cases
        .verify_sources(
            &case.id,
            &source_root,
            SourceCheckMode::Full,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        (
            source_report.total,
            source_report.checked,
            source_report.unchecked
        ),
        (1, 1, 0)
    );
    assert!(source_report.missing_or_changed.is_empty());
    assert_eq!(
        use_cases
            .verify_parquet(&case.id, &CancellationToken::new())
            .unwrap(),
        3
    );
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, &source_root, &CancellationToken::new())
            .unwrap(),
        1
    );
    assert!(
        store
            .text_search(&case.id, "203.0.113.8", 10)
            .unwrap()
            .contains("AssumeRole")
    );
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 1);
    assert!(
        store
            .entity_lookup(&case.id, "ip", "203.0.113.8")
            .unwrap()
            .contains("count=1")
    );
    assert!(
        store
            .neighbors(&case.id, "ip", "203.0.113.8", 10)
            .unwrap()
            .contains("account")
    );
    assert!(
        !store
            .neighbors(&case.id, "ip", "203.0.113.8", 10)
            .unwrap()
            .contains("Partial result")
    );
    assert!(
        store
            .entity_timeline(&case.id, "ip", "203.0.113.8", 10)
            .unwrap()
            .contains("AssumeRole")
    );
    assert!(
        store
            .raw_record(&case.id, hash.as_str(), 0)
            .unwrap()
            .contains("AssumeRole")
    );
    assert!(
        store
            .graph_summary(&case.id)
            .unwrap()
            .contains("Parquet records=1")
    );
    assert!(
        store
            .graph_path(&case.id, ("ip", "203.0.113.8"), ("account", "123456789012"))
            .unwrap()
            .contains("co-observed")
    );
    engine.seal(&case.id).unwrap();
    let manifest_only = root.path().join("manifest-only.irmind");
    irmind_app::export_case(
        &engine,
        store.as_ref(),
        &case.id,
        &manifest_only,
        &CancellationToken::new(),
    )
    .unwrap();
    let report = verify_export_details(&LocalExportVerifier, &manifest_only, None).unwrap();
    assert_eq!(
        (
            report.format_version,
            report.source_manifests,
            report.source_bytes_unavailable
        ),
        (4, 1, 1)
    );
    let with_original = root.path().join("with-original.irmind");
    irmind_app::export_case_v4(
        &engine,
        store.as_ref(),
        &case.id,
        &with_original,
        Some(&source_root),
        true,
        &CancellationToken::new(),
    )
    .unwrap();
    let report = verify_export_details(&LocalExportVerifier, &with_original, None).unwrap();
    assert_eq!(
        (
            report.source_bytes_verified,
            report.source_bytes_unavailable
        ),
        (1, 0)
    );
    let mut altered = fs::read(&with_original).unwrap();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    fs::write(&with_original, altered).unwrap();
    assert!(verify_export_details(&LocalExportVerifier, &with_original, None).is_err());
    fs::write(&path, b"changed").unwrap();
    let changed = use_cases
        .verify_sources(
            &case.id,
            &source_root,
            SourceCheckMode::Full,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(changed.missing_or_changed, vec![hash.as_str().to_owned()]);
    assert_eq!(engine.verify(&case.id).unwrap(), 6);
}

#[test]
fn neighbors_marks_bounded_results_instead_of_claiming_a_complete_count() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("inputs");
    fs::create_dir(&source_root).unwrap();
    let record = serde_json::json!({
        "eventTime": "2026-10-28T12:00:00Z",
        "eventName": "SyntheticNeighbor",
        "recipientAccountId": "123456789012",
        "sourceIPAddress": "203.0.113.8"
    });
    let body = std::iter::repeat_n(record.to_string(), 4097)
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        source_root.join("cloudtrail.json"),
        format!("{{\"Records\":[{body}]}}"),
    )
    .unwrap();
    let store = super::super::ParquetStore::open(root.path()).unwrap();
    let case_id = CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap();
    let prepared = store
        .prepare_local(
            &case_id,
            &source_root,
            "cloudtrail.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    let output = store
        .neighbors_native(
            &case_id,
            &prepared.artifacts,
            &irmind_domain::GraphQueryFilter::default(),
            ("ip", "203.0.113.8"),
            10,
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(output.contains("account 123456789012 co-observed 4096 times"));
    assert!(output.contains("Partial result: sampled 4096 matching records"));
}

#[test]
fn parallel_batch_signs_sources_in_order_and_reuses_identical_artifact() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("inputs");
    fs::create_dir(&source_root).unwrap();
    let content = br#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"ConsoleLogin"}"#;
    fs::write(source_root.join("b.json"), content).unwrap();
    fs::write(source_root.join("a.json"), content).unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[72u8; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
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
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("batch", "account 123456789012").unwrap();
    let cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    let result = cases
        .ingest_local_batch(
            &case.id,
            &source_root,
            &["b.json".into(), "a.json".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(result[0].0, "a.json");
    assert_eq!(result[1].0, "b.json");
    assert_eq!(result[0].1, result[1].1);
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SourceManifestV1)
            .count(),
        2
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::ParquetArtifactV1)
            .count(),
        3
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 6);
    fs::write(source_root.join("a.json"), b"changed").unwrap();
    assert!(
        cases
            .ingest_local(
                &case.id,
                &source_root,
                "a.json",
                false,
                &CancellationToken::new(),
            )
            .is_err()
    );
    assert_eq!(engine.verify(&case.id).unwrap(), 6);
}
