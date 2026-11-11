use super::*;
use sha2::{Digest, Sha256};

fn artifact() -> ParquetArtifactV2 {
    let partition = ArtifactPartitionV2 {
        date: "2026-11-04".into(),
        key_set: ARTIFACT_V2_SCOPE_KEYS.into(),
        policy: ARTIFACT_V2_PARTITION_POLICY.into(),
        tuple_cap: ARTIFACT_V2_MAX_DATE_TUPLES,
        all_scope_overflow: false,
        scopes: vec![
            ScopePartitionV2 {
                key: ScopePartitionKey::Account,
                cap: 1024,
                value: ScopePartitionValue::Ordinary("synthetic".into()),
            },
            ScopePartitionV2 {
                key: ScopePartitionKey::Region,
                cap: 1024,
                value: ScopePartitionValue::Ordinary("eu-west-1".into()),
            },
        ],
    };
    ParquetArtifactV2 {
        path: format!("{}part.events.parquet", partition.path_prefix().unwrap()),
        size: 42,
        sha256: EvidenceHash::parse(&"b".repeat(64)).unwrap(),
        parser_id: "parser-json".into(),
        parser_version: "json-stream-v2".into(),
        schema: ArtifactSchemaV2::CommonEvents,
        partition,
        source_hashes: vec![EvidenceHash::parse(&"a".repeat(64)).unwrap()],
        time_semantics: ARTIFACT_V2_TIME_SEMANTICS.into(),
        stable_order: ARTIFACT_V2_STABLE_ORDER.into(),
        builder_version: "parquet-builder-common-event-direct-v1".into(),
        superseded_hashes: Vec::new(),
    }
}

#[test]
fn unknown_semantics_schema_versions_counts_and_trailing_bytes_fail_closed() {
    let golden = artifact().encode().unwrap();
    for (from, to) in [
        (ARTIFACT_V2_TIME_SEMANTICS, "utc-milliseconds"),
        (ARTIFACT_V2_STABLE_ORDER, "worker-order"),
        (ARTIFACT_V2_SCOPE_KEYS, "scope-partitions-v9"),
        (ARTIFACT_V2_PARTITION_POLICY, "nfkc-unknown-version"),
        ("irmind-events-v4", "irmind-events-v3"),
        ("account", "cluster"),
        ("region", "tenant"),
        ("region", "unknown-key"),
    ] {
        let bytes = decode_payload(&golden, TAG).unwrap();
        let mut old = Vec::new();
        put(&mut old, from.as_bytes());
        let position = bytes.windows(old.len()).position(|v| v == old).unwrap();
        let mut modified = bytes[..position].to_vec();
        put(&mut modified, to.as_bytes());
        modified.extend_from_slice(&bytes[position + old.len()..]);
        assert!(
            ParquetArtifactV2::decode(&encode_payload(&modified).unwrap()).is_err(),
            "{to}"
        );
    }
    assert!(ParquetArtifactV2::decode(&format!("{golden}00")).is_err());
    assert!(ParquetArtifactV2::decode(&"00".repeat(16_385)).is_err());
    assert!(ParquetArtifactV2::decode(&golden[..golden.len() - 2]).is_err());
    let mut bytes = decode_payload(&golden, TAG).unwrap();
    let n = bytes.len();
    bytes[n - 8..].copy_from_slice(&129_u64.to_be_bytes());
    assert!(ParquetArtifactV2::decode(&encode_payload(&bytes).unwrap()).is_err());
}

#[test]
fn source_supersession_and_payload_limits_are_strict() {
    let original = artifact();
    let mut value = original.clone();
    value.source_hashes.push(value.source_hashes[0].clone());
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.source_hashes.clear();
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value
        .source_hashes
        .insert(0, EvidenceHash::parse(&"c".repeat(64)).unwrap());
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.superseded_hashes.push(value.sha256.clone());
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.parser_version = "a".repeat(129);
    assert!(value.encode().is_err());
    let mut value = original;
    value.superseded_hashes = vec![EvidenceHash::parse(&"0".repeat(64)).unwrap()];
    assert_eq!(
        ParquetArtifactV2::decode(&value.encode().unwrap()).unwrap(),
        value
    );
    for count in [128, 129] {
        value.source_hashes = (0..count)
            .map(|i| EvidenceHash::parse(&format!("{i:064x}")).unwrap())
            .collect();
        assert_eq!(value.encode().is_ok(), count == 128);
    }
    value.source_hashes = (0..128)
        .map(|i| EvidenceHash::parse(&format!("{i:064x}")).unwrap())
        .collect();
    value.superseded_hashes = (0..128)
        .map(|i| EvidenceHash::parse(&format!("{:064x}", i + 128)).unwrap())
        .collect();
    assert!(
        value.encode().is_err(),
        "combined lists must fit the unchanged 16 KiB ceiling"
    );
}

#[test]
fn generic_keys_are_canonical_reserved_keys_are_rejected_and_values_never_become_paths() {
    let original = artifact();
    for invalid in [
        "../secret",
        "host/name",
        "a\\b",
        "x://host",
        "UPPER",
        "",
        "a\u{202e}b",
        "a\u{200b}b",
        "é",
        ".",
        "..",
    ] {
        let mut value = original.clone();
        value.partition.scopes[0].value = ScopePartitionValue::Ordinary(invalid.into());
        assert!(value.encode().is_err(), "{invalid}");
    }
    assert!(!original.path.contains("synthetic"));
    assert!(!original.path.contains("eu-west-1"));
    let mut value = original.clone();
    value.partition.scopes.reverse();
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.partition.scopes[1].key = ScopePartitionKey::Account;
    assert!(value.encode().is_err());
    for key in [ScopePartitionKey::Cluster, ScopePartitionKey::Tenant] {
        let mut value = original.clone();
        value.partition.scopes = vec![ScopePartitionV2 {
            key,
            cap: 64,
            value: ScopePartitionValue::Ordinary("x".into()),
        }];
        assert!(value.encode().is_err());
    }
    for cap in [0, 1025] {
        let mut value = original.clone();
        value.partition.scopes[0].cap = cap;
        assert!(value.encode().is_err());
    }
    for suffix in [
        "\x1b[31m.parquet",
        "line\nbreak.parquet",
        "../part.parquet",
        "C:part.parquet",
    ] {
        let mut value = original.clone();
        value.path = format!("{}{suffix}", value.partition.path_prefix().unwrap());
        assert!(value.encode().is_err());
    }
    let mut value = original.clone();
    value.path = value.path.replace("date=2026-11-04", "date=2026-11-05");
    assert!(value.encode().is_err());
    let mut value = original;
    value.partition.date = "2026-02-29".into();
    assert!(value.encode().is_err());
}

#[test]
fn overflow_is_typed_signed_and_cannot_be_impersonated_by_a_host() {
    let mut value = artifact();
    value.partition.scopes = vec![ScopePartitionV2 {
        key: ScopePartitionKey::Host,
        cap: 64,
        value: ScopePartitionValue::Overflow(PartitionOverflowReason::Cardinality),
    }];
    value.path = format!("{}part.parquet", value.partition.path_prefix().unwrap());
    let overflow_path = value.path.clone();
    assert_eq!(
        ParquetArtifactV2::decode(&value.encode().unwrap()),
        Ok(value.clone())
    );
    value.partition.scopes[0].value =
        ScopePartitionValue::Ordinary("overflow-cardinality-cap64".into());
    value.path = format!("{}part.parquet", value.partition.path_prefix().unwrap());
    assert_ne!(value.path, overflow_path);
    for reason in [
        PartitionOverflowReason::TupleBudget,
        PartitionOverflowReason::UnrepresentableValue,
    ] {
        value.partition.scopes[0].value = ScopePartitionValue::Overflow(reason);
        value.partition.all_scope_overflow = reason == PartitionOverflowReason::TupleBudget;
        value.path = format!("{}part.parquet", value.partition.path_prefix().unwrap());
        assert_eq!(
            ParquetArtifactV2::decode(&value.encode().unwrap()),
            Ok(value.clone())
        );
    }
    value.partition.all_scope_overflow = true;
    assert!(value.encode().is_err());
}

#[test]
fn common_schema_envelopes_match_independent_golden_bytes() {
    for (schema, golden, expected_hash) in [
        (
            ArtifactSchemaV2::CommonEvents,
            include_str!("../../../tests/fixtures/common-artifact-events-v2.hex"),
            include_str!("../../../tests/fixtures/common-artifact-events-v2.sha256"),
        ),
        (
            ArtifactSchemaV2::CommonEntities,
            include_str!("../../../tests/fixtures/common-artifact-entities-v2.hex"),
            include_str!("../../../tests/fixtures/common-artifact-entities-v2.sha256"),
        ),
        (
            ArtifactSchemaV2::CommonCoobservations,
            include_str!("../../../tests/fixtures/common-artifact-coobservations-v2.hex"),
            include_str!("../../../tests/fixtures/common-artifact-coobservations-v2.sha256"),
        ),
    ] {
        let mut value = artifact();
        value.schema = schema;
        value.builder_version = "parquet-builder-common-event-v1".into();
        assert_eq!(value.encode().unwrap(), golden.trim());
        assert_eq!(ParquetArtifactV2::decode(golden.trim()).unwrap(), value);
        let bytes = decode_payload(golden.trim(), TAG).unwrap();
        assert_eq!(
            encode_payload(&Sha256::digest(bytes)).unwrap(),
            expected_hash.trim()
        );
    }
}
