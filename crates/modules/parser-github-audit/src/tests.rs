use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1, SourceValue},
};

const CSV: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-github-audit/source/export.csv");
const JSON: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-github-audit/source/export.json");
const STREAM: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-github-audit/source/stream.ndjson");

#[test]
fn native_export_contract_covers_csv_json_and_streaming_records() {
    for (name, bytes, count) in [
        ("export.csv", CSV, 2),
        ("export.json", JSON, 2),
        ("stream.ndjson", STREAM, 4),
    ] {
        irmind_testkit::run_log_parser_contract(
            &GitHubAuditParser,
            &GitHubAuditSourceDecoder,
            name,
            bytes,
            count,
            None,
        )
        .unwrap();
    }
    assert!(
        GitHubAuditParser
            .detect(
                "audit.json",
                br#"{"action":"team.create","created_at":1767531600123}"#
            )
            .is_none()
    );
}

#[test]
fn exact_millisecond_time_and_token_metadata_are_preserved() {
    let (_, rows) = decode("stream.ndjson", STREAM);
    let time = rows[0].timestamp().unwrap();
    assert_eq!(
        time,
        irmind_domain::IndexedTime::from_rfc3339("2026-01-04T13:00:00.123Z", false).unwrap()
    );
    let fields = rows[0].fields();
    assert_eq!(
        fields.field("hashed_token").and_then(SourceValue::as_text),
        Some("synthetic-token-digest")
    );
    assert_eq!(
        fields
            .field("programmatic_access_type")
            .and_then(SourceValue::as_text),
        Some("OAuth access token")
    );
    assert!(fields.field("token_scopes").is_some());
}

#[test]
fn csv_keeps_physical_offsets_and_skips_only_the_bad_record() {
    let header = CSV.split_inclusive(|byte| *byte == b'\n').next().unwrap();
    let body = &CSV[header.len()..];
    let bytes = [header, b"too,few,columns\n", body].concat();
    let (report, rows) = decode("export.csv", &bytes);
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert_eq!(rows[0].origin().offset(), Some((header.len() + 16) as u64));
    assert_eq!(
        rows[0]
            .fields()
            .field("token_scopes")
            .and_then(SourceValue::as_text),
        Some("repo,read:org")
    );
}

fn decode(name: &str, mut bytes: &[u8]) -> (irmind_app::ParseReport, Vec<SourceRecordV1>) {
    let source = SourceReferenceV1::file(name).unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let report = GitHubAuditSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes,
            },
            &mut |record| {
                record.inspect(|row| records.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, records)
}
