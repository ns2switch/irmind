#![allow(clippy::unwrap_used)]

use super::*;
use irmind_mod_parser_json::JsonParser;

#[test]
fn source_and_parquet_are_streamed_and_verified_independently() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let input = sources.join("events.json");
    fs::write(&input, br#"{"Records":[{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4"}]}"#).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let prepared = store
        .prepare_local(
            &id,
            &sources,
            "events.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(prepared.records, 1);
    assert_eq!(prepared.artifacts.len(), 2);
    assert!(!prepared.manifest.copied);
    assert!(
        prepared.artifacts[0]
            .path
            .contains("date=2026-10-28/account=123456789012/region=eu-west-1")
    );
    store
        .verify_local_source(&sources, &prepared.manifest, &CancellationToken::new())
        .unwrap();
    store
        .verify_artifact(&id, &prepared.artifacts[0], &CancellationToken::new())
        .unwrap();
    fs::write(&input, b"changed").unwrap();
    assert!(
        store
            .verify_local_source(&sources, &prepared.manifest, &CancellationToken::new())
            .is_err()
    );
    store
        .verify_artifact(&id, &prepared.artifacts[0], &CancellationToken::new())
        .unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn parquet_queries_preserve_the_previous_corpus_results() {
    // These exact results were captured by comparing both query implementations on this corpus.
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    fs::write(sources.join("events.json"), br#"{"Records":[
        {"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4"},
        {"eventTime":"2026-10-28T12:05:00Z","eventName":"ConsoleLogin","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.5"},
        {"eventTime":"2026-10-28T12:10:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4"}
    ]}"#).unwrap();
    let id = CaseId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let prepared = store
        .prepare_local(
            &id,
            &sources,
            "events.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    let artifacts = &prepared.artifacts;
    let filter = irmind_domain::GraphQueryFilter::default();
    let cancel = CancellationToken::new();
    let hash = prepared.manifest.sha256.as_str();
    assert_eq!(
        store
            .search_native(&id, artifacts, &filter, "AssumeRole", 10, &cancel)
            .unwrap(),
        format!(
            "2026-10-28T12:10:00Z AssumeRole source={hash}#2\n2026-10-28T12:00:00Z AssumeRole source={hash}#0"
        )
    );
    let timeline = store
        .timeline_native(&id, artifacts, &filter, 10, &cancel)
        .unwrap();
    assert_eq!(
        timeline
            .iter()
            .map(|entry| entry.record_index)
            .collect::<Vec<_>>(),
        [2, 1, 0]
    );
    assert!(timeline.iter().all(|entry| entry.evidence_hash == hash));
    assert_eq!(
        store
            .entity_native(&id, artifacts, &filter, "ip", "203.0.113.4", &cancel)
            .unwrap(),
        "ip 203.0.113.4: count=2; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z"
    );
    assert_eq!(
        store
            .entity_native(&id, artifacts, &filter, "account", "123456789012", &cancel)
            .unwrap(),
        "account 123456789012: count=3; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z"
    );
    assert_eq!(
        store
            .entity_timeline_native(&id, artifacts, &filter, ("ip", "203.0.113.4"), 10, &cancel)
            .unwrap(),
        format!(
            "2026-10-28T12:10:00Z AssumeRole source={hash}#2\n2026-10-28T12:00:00Z AssumeRole source={hash}#0"
        )
    );
    assert_eq!(
        store
            .neighbors_native(&id, artifacts, &filter, ("ip", "203.0.113.4"), 10, &cancel)
            .unwrap(),
        "account 123456789012 co-observed 2 times"
    );
    assert_eq!(
        store
            .neighbors_native(
                &id,
                artifacts,
                &filter,
                ("account", "123456789012"),
                10,
                &cancel
            )
            .unwrap(),
        "ip 203.0.113.4 co-observed 2 times\nip 203.0.113.5 co-observed 1 times"
    );
    assert_eq!(
        store
            .path_native(
                &id,
                artifacts,
                &filter,
                ("ip", "203.0.113.4"),
                ("account", "123456789012"),
                &cancel
            )
            .unwrap(),
        format!("ip 203.0.113.4 --[co-observed in {hash}#0]--> account 123456789012")
    );
    let raw = store
        .raw_native(&id, artifacts, hash, 0, &cancel)
        .unwrap()
        .unwrap();
    let expected = r#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4"}"#;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
        serde_json::from_str::<serde_json::Value>(expected).unwrap()
    );
    assert_eq!(
        store.summary_native(&id, artifacts, &cancel).unwrap(),
        "Parquet records=3; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z"
    );
    let narrowed = irmind_domain::GraphQueryFilter::parse(
        Some("2026-10-28T12:04:00Z"),
        Some("2026-10-28T12:10:00Z"),
        Some("123456789012"),
        None,
        Some("eu-west-1"),
    )
    .unwrap();
    assert_eq!(
        store
            .search_native(&id, artifacts, &narrowed, "AssumeRole", 10, &cancel)
            .unwrap(),
        format!("2026-10-28T12:10:00Z AssumeRole source={hash}#2")
    );
    assert_eq!(
        store
            .timeline_native(&id, artifacts, &narrowed, 10, &cancel)
            .unwrap()
            .iter()
            .map(|entry| entry.record_index)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    let tampered = store.case_dir(&id).unwrap().join(&artifacts[0].path);
    fs::write(tampered, b"changed").unwrap();
    assert!(matches!(
        store.summary_native(&id, artifacts, &cancel),
        Err(AppError::EvidenceMismatch(_))
    ));
}
