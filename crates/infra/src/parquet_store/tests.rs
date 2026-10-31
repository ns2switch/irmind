#![allow(clippy::unwrap_used)]

use super::*;
use irmind_mod_parser_json::JsonParser;
use parquet::file::properties::ReaderProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::serialized_reader::ReadOptionsBuilder;

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
    assert_eq!(prepared.artifacts.len(), 3);
    assert!(prepared.artifacts.iter().any(|artifact| {
        artifact.schema_version == "irmind-coobservations-v1"
            && artifact.source_hashes == vec![prepared.manifest.sha256.clone()]
    }));
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
fn new_entity_artifact_has_a_value_bloom_filter() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("events.json"),
        br#"{"Records":[{"eventTime":"2026-10-28T12:00:00Z","eventName":"Read","recipientAccountId":"123456789012","sourceIPAddress":"203.0.113.5"},{"eventTime":"2026-10-28T12:00:01Z","eventName":"Read","recipientAccountId":"123456789012","sourceIPAddress":"203.0.113.4"}]}"#,
    )
    .unwrap();
    let id = CaseId::parse("44444444-4444-4444-4444-444444444444").unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let prepared = store
        .prepare_local(
            &id,
            root.path(),
            "events.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    let artifact = prepared
        .artifacts
        .iter()
        .find(|artifact| artifact.schema_version == "irmind-entities-v2")
        .unwrap();
    let file = File::open(store.case_dir(&id).unwrap().join(&artifact.path)).unwrap();
    let reader = SerializedFileReader::new_with_options(
        file,
        ReadOptionsBuilder::new()
            .with_reader_properties(
                ReaderProperties::builder()
                    .set_read_bloom_filter(true)
                    .build(),
            )
            .build(),
    )
    .unwrap();
    let group = reader.get_row_group(0).unwrap();
    let bloom = group.get_column_bloom_filter(5).unwrap();
    assert!(bloom.check(&"203.0.113.4"));
    let batches = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        File::open(store.case_dir(&id).unwrap().join(&artifact.path)).unwrap(),
    )
    .unwrap()
    .build()
    .unwrap();
    let mut keys = Vec::new();
    for batch in batches {
        let batch = batch.unwrap();
        let kinds = batch
            .column_by_name("entity_kind")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let values = batch
            .column_by_name("entity_value")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        for row in 0..batch.num_rows() {
            keys.push((kinds.value(row).to_owned(), values.value(row).to_owned()));
        }
    }
    assert!(keys.windows(2).all(|pair| pair[0] <= pair[1]));
}

#[test]
#[allow(clippy::too_many_lines)]
fn old_entity_artifacts_remain_queryable_and_rebuildable() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    fs::write(
        sources.join("events.json"),
        br#"{"Records":[{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4"}]}"#,
    )
    .unwrap();
    let old_id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let new_id = CaseId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    let mut store = ParquetStore::open(root.path()).unwrap();
    store.legacy_entities = true;
    let old = store
        .prepare_local(
            &old_id,
            &sources,
            "events.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    store.legacy_entities = false;
    let new = store
        .prepare_local(
            &new_id,
            &sources,
            "events.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(old.artifacts.len(), 2);
    assert_eq!(new.artifacts.len(), 3);
    let filter = irmind_domain::GraphQueryFilter::default();
    let cancel = CancellationToken::new();
    let lookup = |id: &CaseId, artifacts: &[ParquetArtifactV1]| {
        (
            store
                .entity_native(id, artifacts, &filter, "ip", "203.0.113.4", &cancel)
                .unwrap(),
            store
                .neighbors_native(id, artifacts, &filter, ("ip", "203.0.113.4"), 10, &cancel)
                .unwrap(),
            store
                .path_native(
                    id,
                    artifacts,
                    &filter,
                    ("ip", "203.0.113.4"),
                    ("account", "123456789012"),
                    &cancel,
                )
                .unwrap(),
        )
    };
    assert_eq!(
        lookup(&old_id, &old.artifacts),
        lookup(&new_id, &new.artifacts)
    );
    assert_eq!(
        store
            .rebuild_compare(
                &old_id,
                &sources,
                &[old.manifest],
                &old.artifacts,
                &JsonParser,
                &cancel
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .rebuild_compare(
                &new_id,
                &sources,
                &[new.manifest],
                &new.artifacts,
                &JsonParser,
                &cancel
            )
            .unwrap(),
        1
    );
}

#[test]
fn mixed_old_and_new_artifacts_keep_full_neighbor_results() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    for (name, ip) in [("old.json", "203.0.113.4"), ("new.json", "203.0.113.5")] {
        fs::write(
            sources.join(name),
            format!("{{\"Records\":[{{\"eventTime\":\"2026-10-28T12:00:00Z\",\"eventName\":\"Read\",\"recipientAccountId\":\"123456789012\",\"sourceIPAddress\":\"{ip}\"}}]}}"),
        )
        .unwrap();
    }
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    let mut store = ParquetStore::open(root.path()).unwrap();
    store.legacy_entities = true;
    let old = store
        .prepare_local(
            &id,
            &sources,
            "old.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    store.legacy_entities = false;
    let new = store
        .prepare_local(
            &id,
            &sources,
            "new.json",
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    let artifacts = old
        .artifacts
        .into_iter()
        .chain(new.artifacts)
        .collect::<Vec<_>>();
    let result = store
        .neighbors_native(
            &id,
            &artifacts,
            &irmind_domain::GraphQueryFilter::default(),
            ("account", "123456789012"),
            10,
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(result.contains("ip 203.0.113.4 co-observed 1 times"));
    assert!(result.contains("ip 203.0.113.5 co-observed 1 times"));
    assert_eq!(
        store
            .rebuild_compare(
                &id,
                &sources,
                &[old.manifest, new.manifest],
                &artifacts,
                &JsonParser,
                &CancellationToken::new(),
            )
            .unwrap(),
        2
    );
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
    let coobservations = artifacts
        .iter()
        .find(|artifact| artifact.schema_version == "irmind-coobservations-v1")
        .unwrap();
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
    fs::write(
        store.case_dir(&id).unwrap().join(&coobservations.path),
        b"changed",
    )
    .unwrap();
    assert!(matches!(
        store.neighbors_native(&id, artifacts, &filter, ("ip", "203.0.113.4"), 10, &cancel),
        Err(AppError::EvidenceMismatch(_))
    ));
    let tampered = store.case_dir(&id).unwrap().join(&artifacts[0].path);
    fs::write(tampered, b"changed").unwrap();
    assert!(matches!(
        store.summary_native(&id, artifacts, &cancel),
        Err(AppError::EvidenceMismatch(_))
    ));
}
