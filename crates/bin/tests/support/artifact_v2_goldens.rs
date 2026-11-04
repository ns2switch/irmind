use irmind_app::{IndexedTime, TimePrecision, hex, sha256};
use irmind_domain::{AuditEventKind, ParquetArtifactV2};

#[test]
fn new_artifact_bytes_and_hash_do_not_depend_on_json_map_order_or_platform() {
    let wire = include_str!("../../../domain/tests/fixtures/parquet-artifact-v2.hex").trim();
    let expected_hash =
        include_str!("../../../domain/tests/fixtures/parquet-artifact-v2.sha256").trim();
    let artifact = ParquetArtifactV2::decode(wire).unwrap();
    assert_eq!(artifact.encode().unwrap(), wire);
    assert_eq!(artifact.parser_id, "parser-json");
    assert_eq!(artifact.parser_version, "json-stream-v2");
    let bytes = wire
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(hex(&sha256(&bytes)), expected_hash);
    let time = IndexedTime::from_rfc3339("1969-12-31T23:59:59.999999900Z", true).unwrap();
    assert_eq!(time.instant().unix_micros(), -1);
    assert_eq!(time.instant().submicro_nanos(), 900);
    assert_eq!(time.precision(), TimePrecision::Nanosecond);
    assert!(time.inferred());
    let kind = AuditEventKind::ParquetArtifactV2;
    assert_eq!(AuditEventKind::parse(kind.as_str()), Ok(kind));
}

#[test]
fn precise_parquet_physical_bytes_and_envelopes_are_portable() {
    use irmind_app::{CancellationToken, LargeCaseStore};
    let root = tempfile::tempdir().unwrap();
    let input = br#"{"Records":[{"eventTime":"1969-12-31T23:59:59.999999900Z","eventName":"BeforeEpoch","sourceIPAddress":"203.0.113.4"},{"eventTime":"2026-11-01T00:00:00.000000Z","eventName":"MicroZero","sourceIPAddress":"203.0.113.4"},{"eventName":"NoTime","sourceIPAddress":"203.0.113.4"}]}"#;
    std::fs::write(root.path().join("synthetic.json"), input).unwrap();
    let store = irmind_infra::ParquetStore::open_precise(root.path()).unwrap();
    let id = irmind_domain::CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let prepared = store
        .prepare_local(
            &id,
            root.path(),
            "synthetic.json",
            false,
            &irmind_mod_parser_json::JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    let mut actual = std::collections::BTreeMap::new();
    for artifact in prepared.artifacts {
        actual.insert(artifact.path().to_owned(), serde_json::json!({"size": artifact.size(), "sha256": artifact.sha256().as_str(), "envelope": artifact.encode().unwrap()}));
    }
    let expected: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(include_str!("../fixtures/formats-artifact-v2.json")).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn partitioned_parquet_physical_bytes_and_envelopes_are_portable() {
    use irmind_app::{CancellationToken, LargeCaseStore, LocalBatchRequest, PartitionLimits};
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("a.jsonl"),
        include_bytes!("../../../testkit/fixtures/artifact-v2-partitions/a.jsonl"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("b.json"),
        include_bytes!("../../../testkit/fixtures/artifact-v2-partitions/b.json"),
    )
    .unwrap();
    let store = irmind_infra::ParquetStore::open_precise(root.path()).unwrap();
    let id = irmind_domain::CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let paths = ["a.jsonl".into(), "b.json".into()];
    let prepared = store
        .prepare_local_batch(
            LocalBatchRequest {
                case_id: &id,
                source_root: root.path(),
                relative_paths: &paths,
                copy_original: false,
                parser: &irmind_mod_parser_json::JsonParser,
                committed_artifacts: &[],
                limits: PartitionLimits {
                    host: 1,
                    ..PartitionLimits::default()
                },
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let mut actual = std::collections::BTreeMap::new();
    for artifact in prepared.into_iter().flat_map(|source| source.artifacts) {
        actual.insert(artifact.path().to_owned(), serde_json::json!({"size":artifact.size(),"sha256":artifact.sha256().as_str(),"envelope":artifact.encode().unwrap()}));
    }
    let expected: std::collections::BTreeMap<String, serde_json::Value> = serde_json::from_str(
        include_str!("../fixtures/formats-artifact-v2-partitions.json"),
    )
    .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn generations_distinguish_builder_and_parser_without_using_bucket_names() {
    let old = ParquetArtifactV2::decode(
        include_str!("../../../domain/tests/fixtures/parquet-artifact-v2.hex").trim(),
    )
    .unwrap();
    let baseline = irmind_domain::ParquetArtifact::V2(old.clone());
    let mut changed = old.clone();
    changed.builder_version.push_str("-new");
    assert!(!baseline.same_generation(&changed.into()));
    let mut changed = old;
    changed.parser_version.push_str("-new");
    assert!(!baseline.same_generation(&changed.into()));
    assert!(baseline.same_generation(&baseline));
}

#[test]
fn v2_seal_inventory_golden_is_portable_with_either_json_map_implementation() {
    let golden = include_str!("../../../domain/tests/fixtures/seal-inventory-v2.hex").trim();
    let expected = include_str!("../../../domain/tests/fixtures/seal-inventory-v2.sha256").trim();
    let root = irmind_domain::SealInventoryV2::decode(golden).unwrap();
    assert_eq!(root.count, 3);
    assert_eq!(root.encode().unwrap(), golden);
    let bytes = golden
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(hex(&sha256(&bytes)), expected);
}
