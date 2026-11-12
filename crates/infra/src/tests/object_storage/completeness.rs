use super::*;
#[test]
fn large_cloud_object_preserves_every_record_and_signed_hash() {
    let mut bytes=br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"First","recipientAccountId":"123","awsRegion":"eu-west-1"}]}"#.to_vec();
    bytes.resize(4 * 1024 * 1024 + 1024, b' ');
    bytes.extend_from_slice(br#"{"Records":[{"eventTime":"2026-10-23T12:01:00Z","eventName":"Hidden","recipientAccountId":"123","awsRegion":"eu-west-1"}]}"#);
    assert_object(URI, bytes, 2, 0);
}

#[test]
fn logical_ndjson_name_preserves_rejection_semantics_through_random_spool_names() {
    let row = br#"{"eventVersion":"1.09","eventTime":"2026-10-23T12:00:00Z","eventName":"Login"}"#;
    let mut bytes = row.to_vec();
    bytes.resize(5 * 1024 * 1024, b' ');
    bytes.extend_from_slice(row);
    bytes.push(b'\n');
    bytes.extend_from_slice(row);
    bytes.push(b'\n');
    assert_object("s3://synthetic-audit/AWSLogs/123/a.ndjson", bytes, 1, 1);
}

#[allow(clippy::too_many_lines)]
fn assert_object(uri: &'static str, bytes: Vec<u8>, count: usize, rejected: u64) {
    let root = tempfile::tempdir().unwrap();
    let (store, registry) = current_object_pipeline(root.path());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[93; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
    let source = FakeObjectSource {
        uri,
        bytes,
        reads: AtomicUsize::new(0),
        stream_mode: AtomicUsize::new(0),
        spool_probe: std::sync::Mutex::new(None),
    };
    let rules = PolicyRules {
        max_object_read_bytes: 8 * 1024 * 1024,
        max_object_bytes_per_case: 16 * 1024 * 1024,
        object_transfer_approval_bytes: 128,
        ..PolicyRules::default()
    };
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
    .unwrap()
    .with_large_case_pipeline(store.clone(), parser)
    .with_parser_catalog(current_object_parsers(&registry))
    .with_object_source(&source)
    .unwrap()
    .with_policy(rules, "f".repeat(64))
    .unwrap();
    let scope = format!(
        "v3;sources=storage;accounts=;projects=;hosts=;objects=s3://synthetic-audit/AWSLogs/123/;from={FROM};to={TO}"
    );
    let case = engine
        .create_case("Synthetic large cloud object", &scope)
        .unwrap();
    engine
        .request_tool_as_analyst(
            &case.id,
            object_proposal(Tool::ObjectList, "0"),
            &CancellationToken::new(),
        )
        .unwrap();
    let mut call = object_proposal(Tool::ObjectRead, "8388608");
    call.args.insert(
        "key".into(),
        uri.strip_prefix("s3://synthetic-audit/").unwrap().into(),
    );
    let pending = engine
        .request_tool_as_analyst(&case.id, call, &CancellationToken::new())
        .unwrap();
    assert!(pending.starts_with("approval pending:"));
    let approval = engine.pending_approvals(&case.id).unwrap();
    let executed = engine.approve(&case.id, &approval[0].id).unwrap();
    assert!(executed.starts_with("approval executed; evidence "));
    let entries = store.entries(&case.id).unwrap();
    let event = entries
        .iter()
        .find(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .unwrap();
    let manifest = irmind_domain::SourceManifestV2::decode(&event.payload).unwrap();
    assert_eq!(manifest.source.source, uri);
    assert_eq!(manifest.rejected_records, rejected);
    assert_eq!(
        manifest.source.sha256.as_str(),
        irmind_app::hex(&irmind_app::sha256(&source.bytes))
    );
    let events = store.timeline(&case.id, 10).unwrap();
    assert_eq!(events.len(), count);
    assert_eq!(manifest.parser_version, "json-source-v1");
    assert!(
        irmind_app::artifact_catalog(&entries)
            .unwrap()
            .all
            .iter()
            .all(|a| matches!(a, irmind_domain::ParquetArtifact::V3(_)))
    );
    assert!(engine.verify(&case.id).is_ok());
}
