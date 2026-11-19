use super::*;
use irmind_app::{
    CancellationToken, ParseReport, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
use std::io::Write as _;

const ALB: &[u8] = include_bytes!("../../../testkit/fixtures/parser-elb/source/alb.log");
const CLASSIC: &[u8] = include_bytes!("../../../testkit/fixtures/parser-elb/source/classic.log");

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn parse(bytes: &[u8]) -> Result<(ParseReport, Vec<SourceRecordV1>), AppError> {
    let source = SourceReferenceV1::file("elb.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = ElbSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut &bytes[..],
        },
        &mut |record| {
            record.inspect(|row| rows.push(row.clone()));
            Ok(())
        },
    )?;
    Ok((report, rows))
}

#[test]
fn classic_and_application_are_detected_by_layout_and_compressed_offsets_are_absent() {
    for bytes in [ALB, CLASSIC] {
        let zipped = gzip(bytes);
        assert_eq!(ElbParser.detect("copy", bytes).unwrap().value(), 98);
        assert_eq!(ElbParser.detect("copy", &zipped).unwrap().value(), 98);
        let (report, plain) = parse(bytes).unwrap();
        let (zipped_report, compressed) = parse(&zipped).unwrap();
        assert_eq!((report.accepted, report.rejected), (2, 0));
        assert_eq!((zipped_report.accepted, zipped_report.rejected), (2, 0));
        for (first, second) in plain.iter().zip(&compressed) {
            assert_eq!(first.fields(), second.fields());
            assert_eq!(first.timestamp(), second.timestamp());
            assert!(first.origin().offset().is_some());
            assert!(second.origin().offset().is_none());
        }
        let mut corrupt = zipped;
        let footer = corrupt.len() - 5;
        corrupt[footer] ^= 1;
        assert!(parse(&corrupt).is_err());
    }
    assert!(ElbParser.detect("alb.log.gz", b"wrong content").is_none());
}

#[test]
fn query_and_future_fields_remain_literal() {
    let (_, rows) = parse(ALB).unwrap();
    assert_eq!(
        rows[0].fields().field("request_query").unwrap().as_text(),
        Some("arg=%2522")
    );
    assert_eq!(
        rows[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-17T20:00:01.000157Z"
    );
    assert!(rows[0].fields().field("trailing_fields").is_some());
}
