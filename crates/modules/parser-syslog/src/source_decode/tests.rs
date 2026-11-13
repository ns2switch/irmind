#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{
    CancellationToken, ParserTimeBasis, ParserTimeContext, source_mapping::SourceReferenceV1,
};
fn records(
    bytes: &[u8],
    context: Option<&ParserTimeContext>,
) -> Result<(ParseReport, Vec<SourceRecordV1>), AppError> {
    let reference = SourceReferenceV1::file("synthetic.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = SyslogSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: context,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut std::io::Cursor::new(bytes),
        },
        &mut |row| {
            row.inspect(|r| rows.push(r.clone()));
            Ok(())
        },
    )?;
    Ok((report, rows))
}
#[test]
fn modern_headers_remain_original_and_nanos_are_not_rounded() {
    let raw =
        b"<34>1 2026-11-01T00:00:00.123456789Z synthetic-host sshd 42 ID47 - synthetic message\n";
    let (report, rows) = records(raw, None).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(
        rows[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-01T00:00:00.123456789Z"
    );
    assert_eq!(rows[0].origin().offset(), Some(0));
    assert_eq!(
        rows[0].fields().field("app-name").unwrap().as_text(),
        Some("sshd")
    );
    assert!(rows[0].fields().field("event.category").is_none());
}
#[test]
fn classic_requires_context_and_rolls_only_december_into_january() {
    let raw =
        b"<34>Dec 31 23:59:59 host sshd[42]: before\n<34>Jan  1 00:00:01 host sshd[42]: after\n";
    assert!(matches!(
        records(raw, None),
        Err(AppError::ParserTimeContextRequired { .. })
    ));
    let context = ParserTimeContext::new(2026, 0, true, ParserTimeBasis::Analyst).unwrap();
    let (report, rows) = records(raw, Some(&context)).unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(
        rows[1].timestamp().unwrap().to_rfc3339(),
        "2027-01-01T00:00:01Z"
    );
    assert!(rows[1].timestamp().unwrap().inferred());
    let raw=b"<34>Mar  1 00:00:00 host app: first\n<34>Feb  1 00:00:00 host app: invalid regression\n<34>Apr  1 00:00:00 host app: last\n";
    let (report, rows) = records(raw, Some(&context)).unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert_eq!(
        rows[1].timestamp().unwrap().to_rfc3339(),
        "2026-04-01T00:00:00Z"
    );
}
#[test]
fn gzip_is_streamed_without_invented_compressed_record_offsets() {
    use std::io::Write as _;
    let raw = b"<34>1 2026-11-01T00:00:00Z host app 42 - - synthetic\n";
    let mut zip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    zip.write_all(raw).unwrap();
    let bytes = zip.finish().unwrap();
    let (report, rows) = records(&bytes, None).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(rows[0].origin().offset(), None);
    assert_eq!(rows[0].annotations().members()[0].offset, None);
    assert_eq!(rows[0].format().id(), "syslog-gzip");
}

#[test]
fn oversized_whitespace_prefix_is_counted_without_losing_later_rows() {
    let raw = b"<34>1 2026-11-01T00:00:00Z host app 42 - - synthetic\n";
    let prefix = 1024 * 1024 + 1;
    let input = [raw.as_slice(), &vec![b' '; prefix], raw, raw].concat();
    let (report, rows) = records(&input, None).unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert_eq!(rows[1].annotations().members()[0].ordinal, 2);
    assert_eq!(
        rows[1].origin().offset(),
        Some((prefix + 2 * raw.len()) as u64)
    );
}
