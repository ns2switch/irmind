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
