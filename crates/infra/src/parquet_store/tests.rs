#![allow(clippy::unwrap_used)]

use super::*;
use irmind_mod_parser_json::JsonParser;
use parquet::file::properties::ReaderProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::serialized_reader::ReadOptionsBuilder;

#[cfg(windows)]
#[test]
fn concurrent_identical_sources_publish_all_three_artifacts() {
    for _ in 0..16 {
        let root = tempfile::tempdir().unwrap();
        let sources = root.path().join("sources");
        fs::create_dir(&sources).unwrap();
        let content = br#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"ConsoleLogin"}"#;
        fs::write(sources.join("a.json"), content).unwrap();
        fs::write(sources.join("b.json"), content).unwrap();
        let id = CaseId::parse("99999999-9999-9999-9999-999999999999").unwrap();
        let store = crate::parquet_store::fixtures::store(root.path());
        let outcomes = std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                crate::parquet_store::fixtures::one_source(
                    &store,
                    &id,
                    &sources,
                    "a.json",
                    false,
                    &CancellationToken::new(),
                )
            });
            let b = scope.spawn(|| {
                crate::parquet_store::fixtures::one_source(
                    &store,
                    &id,
                    &sources,
                    "b.json",
                    false,
                    &CancellationToken::new(),
                )
            });
            [a.join().unwrap(), b.join().unwrap()]
        });
        for outcome in outcomes {
            assert_eq!(outcome.unwrap().artifacts.len(), 3);
        }
    }
}

#[test]
fn source_and_parquet_are_streamed_and_verified_independently() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let input = sources.join("events.json");
    fs::write(&input, br#"{"Records":[{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4"}]}"#).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let store = crate::parquet_store::fixtures::store(root.path());
    let prepared = crate::parquet_store::fixtures::one_source(
        &store,
        &id,
        &sources,
        "events.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(prepared.records, 1);
    assert_eq!(prepared.artifacts.len(), 3);
    assert!(prepared.artifacts.iter().any(|artifact| {
        artifact.schema_version() == "irmind-coobservations-v3"
            && artifact.source_hashes() == vec![prepared.manifest.sha256.clone()]
    }));
    assert!(!prepared.manifest.copied);
    let core = prepared.artifacts[0].precise_metadata().unwrap();
    assert_eq!(core.partition.date, "2026-10-28");
    assert!(core.partition.scopes.iter().any(|scope| scope.key
        == irmind_domain::ScopePartitionKey::Account
        && scope.value == irmind_domain::ScopePartitionValue::Ordinary("123456789012".into())));
    assert!(!prepared.artifacts[0].path().contains("123456789012"));
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
    let store = crate::parquet_store::fixtures::store(root.path());
    let prepared = crate::parquet_store::fixtures::one_source(
        &store,
        &id,
        root.path(),
        "events.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let artifact = prepared
        .artifacts
        .iter()
        .find(|artifact| artifact.schema_version() == "irmind-entities-v4")
        .unwrap();
    let file = File::open(store.case_dir(&id).unwrap().join(artifact.path())).unwrap();
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
    let value_column = reader
        .metadata()
        .file_metadata()
        .schema_descr()
        .columns()
        .iter()
        .position(|column| column.path().string() == "entity_value")
        .unwrap();
    let bloom = group.get_column_bloom_filter(value_column).unwrap();
    assert!(bloom.check(&"203.0.113.4"));
    let batches = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        File::open(store.case_dir(&id).unwrap().join(artifact.path())).unwrap(),
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
    let store = crate::parquet_store::fixtures::store(root.path());
    let prepared = crate::parquet_store::fixtures::one_source(
        &store,
        &id,
        &sources,
        "events.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let artifacts = &prepared.artifacts;
    let filter = irmind_domain::GraphQueryFilter::default();
    let cancel = CancellationToken::new();
    let hash = prepared.manifest.sha256.as_str();
    let names = BTreeMap::from([(hash.to_owned(), "events.json".into())]);
    assert_eq!(
        store
            .queries(&names)
            .search_native(&id, artifacts, &filter, "AssumeRole", 10, &cancel)
            .unwrap(),
        format!(
            "2026-10-28T12:10:00Z AssumeRole [second precision] source={hash}#2\n2026-10-28T12:00:00Z AssumeRole [second precision] source={hash}#0"
        )
    );
    let timeline = store
        .queries(&names)
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
            .queries(&names)
            .entity_native(&id, artifacts, &filter, "ip", "203.0.113.4", &cancel)
            .unwrap(),
        "ip 203.0.113.4: observations=2; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z; role counts: unspecified=2\nscope=legacy-unspecified: observations=2; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z"
    );
    assert_eq!(
        store
            .queries(&names)
            .entity_native(&id, artifacts, &filter, "account", "123456789012", &cancel)
            .unwrap(),
        "account 123456789012: observations=3; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z; role counts: unspecified=3\nscope=legacy-unspecified: observations=3; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z"
    );
    assert_eq!(
        store
            .queries(&names)
            .entity_timeline_native(&id, artifacts, &filter, ("ip", "203.0.113.4"), 10, &cancel)
            .unwrap(),
        format!(
            "2026-10-28T12:10:00Z AssumeRole [second precision] source={hash}#2\n2026-10-28T12:00:00Z AssumeRole [second precision] source={hash}#0"
        )
    );
    assert_eq!(
        store
            .queries(&names)
            .neighbors_native(&id, artifacts, &filter, ("ip", "203.0.113.4"), 10, &cancel)
            .unwrap(),
        "account 123456789012 [scope=legacy-unspecified] co-observed 2 times"
    );
    assert_eq!(
        store
            .queries(&names)
            .neighbors_native(
                &id,
                artifacts,
                &filter,
                ("account", "123456789012"),
                10,
                &cancel
            )
            .unwrap(),
        "ip 203.0.113.4 [scope={\"kind\":\"global\"}] co-observed 2 times\nip 203.0.113.5 [scope={\"kind\":\"global\"}] co-observed 1 times"
    );
    assert_eq!(
        store
            .queries(&names)
            .path_native(
                &id,
                artifacts,
                &filter,
                ("ip", "203.0.113.4"),
                ("account", "123456789012"),
                &cancel
            )
            .unwrap(),
        format!(
            "ip 203.0.113.4 [matching scoped occurrence] --[co-observed in {hash}#0]--> account 123456789012 [scope=legacy-unspecified]"
        )
    );
    let raw = store
        .queries(&names)
        .raw_native(&id, artifacts, hash, 0, &cancel)
        .unwrap()
        .unwrap();
    let expected = r#"{"eventTime":"2026-10-28T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4"}"#;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
        serde_json::from_str::<serde_json::Value>(expected).unwrap()
    );
    assert_eq!(
        store
            .queries(&names)
            .summary_native(&id, artifacts, &cancel)
            .unwrap(),
        "Parquet records=3; first=2026-10-28T12:00:00Z; last=2026-10-28T12:10:00Z; common records=3/3; categorized=0/3; known outcomes=0/3; other records remain unclassified"
    );
    let coobservations = artifacts
        .iter()
        .find(|artifact| artifact.schema_version() == "irmind-coobservations-v3")
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
            .queries(&names)
            .search_native(&id, artifacts, &narrowed, "AssumeRole", 10, &cancel)
            .unwrap(),
        format!("2026-10-28T12:10:00Z AssumeRole [second precision] source={hash}#2")
    );
    assert_eq!(
        store
            .queries(&names)
            .timeline_native(&id, artifacts, &narrowed, 10, &cancel)
            .unwrap()
            .iter()
            .map(|entry| entry.record_index)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    fs::write(
        store.case_dir(&id).unwrap().join(coobservations.path()),
        b"changed",
    )
    .unwrap();
    assert!(matches!(
        store.queries(&names).neighbors_native(
            &id,
            artifacts,
            &filter,
            ("ip", "203.0.113.4"),
            10,
            &cancel
        ),
        Err(AppError::EvidenceMismatch(_))
    ));
    let events = artifacts
        .iter()
        .find(|artifact| artifact.schema_version() == "irmind-events-v4")
        .unwrap();
    let tampered = store.case_dir(&id).unwrap().join(events.path());
    fs::write(tampered, b"changed").unwrap();
    assert!(matches!(
        store
            .queries(&names)
            .summary_native(&id, artifacts, &cancel),
        Err(AppError::EvidenceMismatch(_))
    ));
}

mod common;
