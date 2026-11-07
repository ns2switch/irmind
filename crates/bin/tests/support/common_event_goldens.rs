use super::*;

#[test]
fn typed_common_payload_and_new_envelopes_are_feature_independent() {
    let wire = include_str!("../../../app/src/common_event/goldens/network-v1.json").trim();
    let event = irmind_app::decode_common_event(wire).unwrap();
    assert_eq!(irmind_app::encode_common_event(&event).unwrap(), wire);
    for wire in [
        include_str!("../../../domain/tests/fixtures/common-artifact-events-v2.hex"),
        include_str!("../../../domain/tests/fixtures/common-artifact-entities-v2.hex"),
        include_str!("../../../domain/tests/fixtures/common-artifact-coobservations-v2.hex"),
    ] {
        assert_eq!(
            irmind_domain::ParquetArtifactV2::decode(wire.trim())
                .unwrap()
                .encode()
                .unwrap(),
            wire.trim()
        );
    }
}

#[test]
fn every_existing_parser_keeps_a_valid_unclassified_bridge() {
    for (_, parser, fixture) in parsers() {
        let count = normalized_rows(
            parser.as_ref(),
            "fixture.json",
            fixture,
            &CancellationToken::new(),
        )
        .len();
        irmind_testkit::run_common_event_contract(parser.as_ref(), "fixture.json", fixture, count)
            .unwrap();
    }
}

#[test]
fn common_parquet_physical_bytes_are_feature_independent() {
    use irmind_app::{LocalBatchRequest, PartitionLimits};
    let root = tempfile::tempdir().unwrap();
    let bytes = br#"{"Records":[{"eventTime":"2026-11-01T00:00:00.123456789Z","eventName":"Observe","sourceIPAddress":"203.0.113.77"},{"eventName":"Unknown","userIdentity":{"userName":"alice"}}]}"#;
    fs::write(root.path().join("synthetic.json"), bytes).unwrap();
    let store = ParquetStore::open_common(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let paths = ["synthetic.json".into()];
    let prepared = store
        .prepare_local_batch(
            LocalBatchRequest {
                case_id: &id,
                source_root: root.path(),
                relative_paths: &paths,
                copy_original: false,
                parser: &JsonParser,
                committed_artifacts: &[],
                limits: PartitionLimits::default(),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let actual = prepared.into_iter().flat_map(|p|p.artifacts).map(|a|(a.path().to_owned(),serde_json::json!({"size":a.size(),"sha256":a.sha256().as_str(),"envelope":a.encode().unwrap()}))).collect::<BTreeMap<_,_>>();
    let expected: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(include_str!("../fixtures/formats-common-event-v1.json")).unwrap();
    assert_eq!(actual, expected);
}
