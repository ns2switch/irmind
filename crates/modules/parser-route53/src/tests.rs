use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};

const ROWS: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-route53/source/queries.ndjson");

#[test]
fn decoder_keeps_native_answers_and_offsets_and_rejects_unknown_major_versions() {
    let selected = Route53Parser.detect("unlabelled", ROWS).unwrap();
    assert_eq!(selected.value(), 98);
    let raw = std::str::from_utf8(ROWS).unwrap();
    let unsupported = raw.lines().next().unwrap().replace("1.100000", "2.0");
    assert!(
        Route53Parser
            .detect("file.json", unsupported.as_bytes())
            .is_none()
    );
    let combined = format!("{ROWS}{unsupported}\n", ROWS = raw);
    let cancel = CancellationToken::new();
    let reference = SourceReferenceV1::file("queries.ndjson").unwrap();
    let offsets = raw.match_indices('\n').map(|(n, _)| n + 1);
    let mut expected = std::iter::once(0).chain(offsets).enumerate();
    let report = Route53SourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(combined.as_bytes()),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut combined.as_bytes(),
            },
            &mut |record| {
                record.inspect(|row| {
                    let (index, offset) = expected.next().unwrap();
                    assert_eq!(row.origin().record(), index as u64);
                    assert_eq!(row.origin().offset(), Some(offset as u64));
                    assert!(row.fields().field("answers").is_some());
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.accepted, 3);
    assert_eq!(report.rejected, 1);
}
