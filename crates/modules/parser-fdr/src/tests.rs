use super::*;
use irmind_app::{
    CancellationToken,
    source_mapping::{SourceRecordV1, SourceValue},
};
use std::io::Write;
const FIXTURE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-fdr/source/events.ndjson");
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
fn rows(bytes: &[u8]) -> (irmind_app::ParseReport, Vec<SourceRecordV1>) {
    let mut output = Vec::new();
    let report = irmind_testkit::decode_source(
        &FdrSourceDecoder,
        "synthetic.data",
        &mut std::io::Cursor::new(bytes),
        irmind_app::sha256(bytes),
        &CancellationToken::new(),
        None,
        &mut |r| {
            r.inspect(|v| output.push(v.clone()));
            Ok(())
        },
    )
    .unwrap();
    (report, output)
}
#[test]
fn contracts_cover_plain_and_gzip_with_real_or_unavailable_offsets() {
    for bytes in [FIXTURE.to_vec(), gzip(FIXTURE)] {
        assert_eq!(
            FdrParser.detect("unrelated.bin", &bytes).unwrap().value(),
            98
        );
        irmind_testkit::run_log_parser_contract(
            &FdrParser,
            &FdrSourceDecoder,
            "synthetic.data",
            &bytes,
            11,
            None,
        )
        .unwrap();
        irmind_testkit::run_decode_budget_contract(&FdrSourceDecoder, "synthetic.data", &bytes)
            .unwrap();
        let (_, records) = rows(&bytes);
        assert!(
            records
                .iter()
                .all(|r| r.origin().offset().is_none() == bytes.starts_with(&[0x1f, 0x8b]))
        );
        assert_eq!(
            records[0].timestamp().unwrap().instant().unix_micros(),
            1_794_918_896_123_000
        );
        assert_eq!(
            records
                .last()
                .unwrap()
                .fields()
                .field("event_simpleName")
                .and_then(SourceValue::as_text),
            Some("FutureUnknownEvent")
        );
    }
}
#[test]
fn invalid_lines_and_oversize_first_record_preserve_following_records() {
    let bytes = [b"{broken}\n".as_slice(), FIXTURE].concat();
    let (report, records) = rows(&bytes);
    assert_eq!((report.accepted, report.rejected), (11, 1));
    assert_eq!(records[0].origin().offset(), Some(9));
    let bytes = [
        vec![b'x'; 5 * 1024 * 1024],
        b"\n".to_vec(),
        FIXTURE.to_vec(),
    ]
    .concat();
    let (report, records) = rows(&bytes);
    assert_eq!((report.accepted, report.rejected), (11, 1));
    assert_eq!(records[0].origin().offset(), Some(5 * 1024 * 1024 + 1));
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}
#[test]
fn gzip_crc_and_cancellation_reject_the_complete_source() {
    let mut bytes = gzip(FIXTURE);
    let at = bytes.len() - 8;
    bytes[at] ^= 1;
    assert!(
        irmind_testkit::decode_source(
            &FdrSourceDecoder,
            "bad.gz",
            &mut bytes.as_slice(),
            [0; 32],
            &CancellationToken::new(),
            None,
            &mut |_| Ok(())
        )
        .is_err()
    );
    let cancel = CancellationToken::new();
    let mut count = 0;
    let result = irmind_testkit::decode_source(
        &FdrSourceDecoder,
        "cancel.ndjson",
        &mut std::io::Cursor::new(FIXTURE),
        [0; 32],
        &cancel,
        None,
        &mut |_| {
            count += 1;
            cancel.cancel();
            Ok(())
        },
    );
    assert!(matches!(result, Err(irmind_app::AppError::Cancelled)));
    assert_eq!(count, 1);
}
