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
