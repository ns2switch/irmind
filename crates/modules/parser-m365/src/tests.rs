use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
const FIXTURE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-m365/source/events.ndjson");
#[test]
fn original_decoder_contract() {
    irmind_testkit::run_log_parser_contract(
        &M365Parser,
        &M365SourceDecoder,
        "events.ndjson",
        FIXTURE,
        8,
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
    let report = M365SourceDecoder
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
    assert_eq!((report.accepted, report.rejected), (8, 1));
    assert_eq!(rows[0].origin().offset(), Some(9));
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}
#[test]
fn extension_alone_is_not_a_format_proof() {
    assert!(
        M365Parser
            .detect("events.m365", b"unrelated input")
            .is_none()
    );
    assert_eq!(
        M365Parser.detect("opaque.bin", FIXTURE).unwrap().value(),
        98
    );
}

#[test]
fn all_three_export_layouts_keep_auditdata_and_unknown_operations() {
    for (name, bytes, count) in [
        (
            "purview.csv",
            include_bytes!("../../../testkit/fixtures/parser-m365/source/purview.csv").as_slice(),
            2,
        ),
        (
            "powershell.json",
            include_bytes!("../../../testkit/fixtures/parser-m365/source/powershell.json")
                .as_slice(),
            2,
        ),
        (
            "activity.json",
            include_bytes!("../../../testkit/fixtures/parser-m365/source/activity.json").as_slice(),
            8,
        ),
    ] {
        assert_eq!(M365Parser.detect(name, bytes).unwrap().value(), 98);
        irmind_testkit::run_log_parser_contract(
            &M365Parser,
            &M365SourceDecoder,
            name,
            bytes,
            count,
            None,
        )
        .unwrap();
    }
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
    let report = M365SourceDecoder
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
