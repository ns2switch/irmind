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
