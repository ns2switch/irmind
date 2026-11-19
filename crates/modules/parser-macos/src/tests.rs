use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};

const UNIFIED: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-macos/source/unified.ndjson");
const ENDPOINT: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-macos/source/endpoint.ndjson");

#[test]
fn both_formats_pass_the_shared_decoder_contract() {
    for (fixture, name, id) in [
        (UNIFIED, "unified.ndjson", "macos-unified-log"),
        (ENDPOINT, "endpoint.ndjson", "macos-eslogger"),
    ] {
        irmind_testkit::run_log_parser_contract(
            &MacosParser,
            &MacosSourceDecoder,
            name,
            fixture,
            2,
            None,
        )
        .unwrap();
        let rows = decoded(name, fixture);
        assert_eq!(rows[0].format().id(), id);
        assert_eq!(rows[0].origin().offset(), Some(0));
        assert_eq!(rows[0].origin().record(), 0);
        assert_eq!(
            rows[1].origin().offset(),
            fixture
                .iter()
                .position(|b| *b == b'\n')
                .map(|i| i as u64 + 1)
        );
    }
    assert_eq!(
        decoded("endpoint.ndjson", ENDPOINT)[0].format().version(),
        "1"
    );
    assert!(
        MacosParser
            .detect("unified.ndjson", b"{\"timestamp\":\"now\"}")
            .is_none()
    );
}

#[test]
fn a_document_preserves_native_macos_records_and_fractional_time() {
    let rows = decoded("unified.ndjson", UNIFIED);
    let document = format!(
        "[\n{},\n{}\n]\n",
        std::str::from_utf8(UNIFIED)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
        std::str::from_utf8(UNIFIED)
            .unwrap()
            .lines()
            .nth(1)
            .unwrap()
    );
    let array = decoded("unified.json", document.as_bytes());
    assert_eq!(rows[0].fields(), array[0].fields());
    assert_eq!(rows[0].timestamp(), array[0].timestamp());
    assert_eq!(array[0].origin().offset(), Some(2));
    let nano_time = decoded("endpoint.ndjson", ENDPOINT)[0].timestamp().unwrap();
    assert_eq!(
        nano_time,
        irmind_domain::IndexedTime::from_rfc3339("2026-01-03T10:12:15.123456789Z", false).unwrap()
    );
}

#[test]
fn unknown_schema_and_event_type_remain_original() {
    let newer = std::str::from_utf8(ENDPOINT)
        .unwrap()
        .replace("\"schema_version\":1", "\"schema_version\":17")
        .replace("\"exec\"", "\"new_event\"");
    let rows = decoded("endpoint.ndjson", newer.as_bytes());
    assert_eq!(rows[0].format().version(), "17");
    assert!(
        rows[0]
            .fields()
            .field("event")
            .unwrap()
            .field("new_event")
            .is_some()
    );
}

fn decoded(name: &str, mut bytes: &[u8]) -> Vec<SourceRecordV1> {
    let source = SourceReferenceV1::file(name).unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let result = MacosSourceDecoder
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
            &mut |row| {
                row.inspect(|row| rows.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(result.rejected, 0);
    assert_eq!(result.accepted, rows.len());
    rows
}

#[test]
fn a_single_line_json_array_larger_than_four_mib_keeps_its_tail() {
    let object = UNIFIED.split(|byte| *byte == b'\n').next().unwrap();
    let count = 5 * 1024 * 1024 / (object.len() + 1) + 1;
    let mut document = Vec::with_capacity(count * (object.len() + 1) + 1);
    document.push(b'[');
    for index in 0..count {
        if index > 0 {
            document.push(b',');
        }
        document.extend_from_slice(object);
    }
    document.push(b']');
    let source = SourceReferenceV1::file("unified.json").unwrap();
    let cancel = CancellationToken::new();
    let mut seen = 0;
    let report = MacosSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(&document),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut document.as_slice(),
            },
            &mut |row| {
                row.inspect(|row| {
                    assert_eq!(row.origin().record(), seen);
                    assert_eq!(
                        row.origin().offset(),
                        Some(1 + seen * (object.len() as u64 + 1))
                    );
                });
                seen += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (count, 0));
}
