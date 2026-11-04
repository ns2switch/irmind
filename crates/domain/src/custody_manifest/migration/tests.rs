use super::*;

fn record() -> ParquetMigrationV1 {
    let set = |count, digit: &str| SetCommitment {
        count,
        sha256: EvidenceHash::parse(&digit.repeat(64)).unwrap(),
    };
    ParquetMigrationV1 {
        sources: set(1, "a"),
        previous: set(3, "b"),
        replacement: set(3, "c"),
        parsers: vec![(
            ParserTransition {
                old_id: "parser-json".into(),
                old_version: "json-stream-v2".into(),
                new_id: "parser-json".into(),
                new_version: "json-stream-v2".into(),
            },
            set(1, "a"),
        )],
        builder_version: "parquet-builder-v3".into(),
        time_semantics: ARTIFACT_V2_TIME_SEMANTICS.into(),
    }
}
#[test]
fn migration_payload_matches_independently_encoded_golden() {
    let golden = include_str!("../../../tests/fixtures/parquet-migration-v1.hex").trim();
    assert_eq!(record().encode().unwrap(), golden);
    assert_eq!(ParquetMigrationV1::decode(golden).unwrap(), record());
    assert!(ParquetMigrationV1::decode(&format!("{golden}00")).is_err());
}
#[test]
fn migration_commitments_require_complete_nonempty_parser_coverage() {
    for count in [0, 2, u64::MAX] {
        let mut value = record();
        value.parsers[0].1.count = count;
        assert!(value.encode().is_err());
    }
    let mut value = record();
    value.replacement.sha256 = value.previous.sha256.clone();
    assert!(value.validate().is_err());
    let mut value = record();
    value.parsers.push(value.parsers[0].clone());
    assert!(value.validate().is_err());
}
