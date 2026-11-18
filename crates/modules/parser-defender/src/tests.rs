use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
const FIXTURE: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-defender/source/events.ndjson");
pub(super) fn rows(bytes: &[u8]) -> (irmind_app::ParseReport, Vec<SourceRecordV1>) {
    let source = SourceReferenceV1::file("synthetic.data").unwrap();
    let cancel = CancellationToken::new();
    let mut output = Vec::new();
    let report = DefenderSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |record| {
                record.inspect(|r| output.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, output)
}
#[test]
fn original_decoder_and_parallel_budget_contracts_cover_all_layouts() {
    for (name, bytes) in [
        ("events.ndjson", FIXTURE),
        (
            "api.json",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/api.json").as_slice(),
        ),
        (
            "stream.json",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/stream.json")
                .as_slice(),
        ),
        (
            "hunting.csv",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/hunting.csv")
                .as_slice(),
        ),
    ] {
        assert_eq!(DefenderParser.detect(name, bytes).unwrap().value(), 98);
        irmind_testkit::run_log_parser_contract(
            &DefenderParser,
            &DefenderSourceDecoder,
            name,
            bytes,
            9,
            None,
        )
        .unwrap();
        irmind_testkit::run_decode_budget_contract(&DefenderSourceDecoder, name, bytes).unwrap();
    }
}
#[test]
fn malformed_rows_do_not_consume_later_events_and_keep_real_offsets() {
    let bytes = [b"{broken}\n".as_slice(), FIXTURE].concat();
    let (report, output) = rows(&bytes);
    assert_eq!((report.accepted, report.rejected), (9, 1));
    assert_eq!(output[0].origin().offset(), Some(9));
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}
#[test]
fn unknown_event_types_and_original_arrays_are_not_discarded() {
    let first = FIXTURE.split(|b| *b == b'\n').next().unwrap();
    let mut text = String::from_utf8(first.to_vec()).unwrap();
    text = text
        .replace("DeviceProcessEvents", "FutureTable")
        .replace("ProcessCreated", "FutureAction");
    text.insert_str(1, "\"events\":[{\"synthetic\":true}],");
    let (report, output) = rows(text.as_bytes());
    assert_eq!(report.accepted, 1);
    assert!(output[0].fields().field("events").is_some());
    assert_eq!(
        output[0]
            .format()
            .discriminators()
            .get(&irmind_domain::SourceDiscriminator::RecordType)
            .map(String::as_str),
        Some("UnknownDeviceEvents")
    );
}

#[test]
fn a_single_line_document_over_four_mib_keeps_every_original_record() {
    let row = FIXTURE.split(|b| *b == b'\n').next().unwrap();
    let count = 5 * 1024 * 1024 / (row.len() + 1) + 1;
    let mut bytes = Vec::with_capacity(count * (row.len() + 1) + 2);
    bytes.push(b'[');
    for index in 0..count {
        if index != 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(row);
    }
    bytes.push(b']');
    assert!(bytes.len() > 4 * 1024 * 1024);
    let source = SourceReferenceV1::file("single-line.json").unwrap();
    let cancel = CancellationToken::new();
    let mut accepted = 0usize;
    let mut last = None;
    let report = DefenderSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(&bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes.as_slice(),
            },
            &mut |record| {
                record.inspect(|record| {
                    assert_eq!(record.origin().record(), accepted as u64);
                    let offset = record.origin().offset().unwrap();
                    assert!(last.is_none_or(|prior| offset > prior));
                    last = Some(offset);
                    accepted += 1;
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        (report.accepted, report.rejected, accepted),
        (count, 0, count)
    );
}
