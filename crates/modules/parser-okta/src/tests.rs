use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
const FIXTURE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-okta/source/events.ndjson");
#[test]
fn original_decoder_contract() {
    irmind_testkit::run_log_parser_contract(
        &OktaParser,
        &OktaSourceDecoder,
        "events.ndjson",
        FIXTURE,
        7,
        None,
    )
    .unwrap();
}
#[test]
fn malformed_line_preserves_the_later_record_and_offset() {
    let bytes = [b"{broken}\n".as_slice(), FIXTURE].concat();
    let source = SourceReferenceV1::file("events.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = OktaSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: [7; 32],
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes.as_slice(),
            },
            &mut |r| {
                r.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (7, 1));
    assert_eq!(rows[0].origin().offset(), Some(9));
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}
#[test]
fn extension_alone_is_not_a_format_proof() {
    assert!(
        OktaParser
            .detect("events.okta", b"unrelated input")
            .is_none()
    );
    assert_eq!(
        OktaParser.detect("opaque.bin", FIXTURE).unwrap().value(),
        98
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
    let report = OktaSourceDecoder
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

#[test]
fn native_events_array_is_original_data_not_an_outer_document() {
    let first = FIXTURE.split(|b| *b == b'\n').next().unwrap();
    let mut bytes = first.strip_suffix(b"}").unwrap().to_vec();
    bytes.extend_from_slice(br#", "events": [{"synthetic_original_extension": true}]}"#);
    irmind_testkit::run_log_parser_contract(
        &OktaParser,
        &OktaSourceDecoder,
        "source.json",
        &bytes,
        1,
        None,
    )
    .unwrap();
    let source = SourceReferenceV1::file("source.json").unwrap();
    let cancel = CancellationToken::new();
    let mut retained = false;
    OktaSourceDecoder
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
                    if let Some(irmind_app::source_mapping::SourceValue::Array(values)) =
                        record.fields().field("events")
                    {
                        retained = values
                            .first()
                            .and_then(|v| v.field("synthetic_original_extension"))
                            == Some(&irmind_app::source_mapping::SourceValue::Boolean(true));
                    }
                });
                Ok(())
            },
        )
        .unwrap();
    assert!(retained);
}
