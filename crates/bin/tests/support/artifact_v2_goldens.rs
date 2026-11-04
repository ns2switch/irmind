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
