use super::*;
use irmind_app::{CancellationToken, source_mapping::SourceReferenceV1};
#[test]
fn oversized_whitespace_prefix_is_counted_in_tsv() {
    let header = b"#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.resp_h\n#types\ttime\tstring\taddr\taddr\n";
    let row = b"1790000000.123456\tCsynthetic\t192.0.2.1\t198.51.100.1\n";
    let prefix = 5 * 1024 * 1024;
    let input = [header.as_slice(), row, &vec![b' '; prefix], row, row].concat();
    let source = SourceReferenceV1::file("conn.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = ZeekSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: [1; 32],
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut input.as_slice(),
            },
            &mut |row| {
                row.inspect(|record| rows.push(record.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert_eq!(rows[1].annotations().members()[0].ordinal, 2);
    assert_eq!(
        rows[1].origin().offset(),
        Some((header.len() + prefix + 2 * row.len()) as u64)
    );
}
