use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
const SIGNIN: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-entra/source/signin-resource.ndjson");
const AUDIT: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-entra/source/audit-resource.ndjson");
const TABLE: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-entra/source/signin-table.ndjson");
const AUDIT_TABLE: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-entra/source/audit-table.ndjson");
fn decode(bytes: &[u8]) -> (irmind_app::ParseReport, Vec<SourceRecordV1>) {
    let source = SourceReferenceV1::file("synthetic.json").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = EntraSourceDecoder
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
                record.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}
#[test]
fn export_layouts_preserve_precise_source_time_names_and_types() {
    for (bytes, format) in [
        (SIGNIN, "entra-signin-resource"),
        (AUDIT, "entra-audit-resource"),
        (TABLE, "entra-signin-table"),
        (AUDIT_TABLE, "entra-audit-table"),
    ] {
        let (report, rows) = decode(bytes);
        assert_eq!((report.accepted, report.rejected), (1, 0));
        assert_eq!(rows[0].format().id(), format);
        assert!(rows[0].cluster_identity().is_none());
        assert_eq!(
            EntraParser.detect("untrusted.bin", bytes).unwrap().value(),
            98
        );
        let fields = irmind_app::source_mapping::json::decode_json_fields(
            bytes,
            irmind_app::source_mapping::json::SourceJsonLimits::default(),
        )
        .unwrap();
        assert_eq!(rows[0].fields(), &fields);
        if format.starts_with("entra-signin") {
            assert_eq!(
                rows[0].timestamp().unwrap().to_rfc3339(),
                "2026-11-01T00:00:00.123456789Z"
            );
        }
    }
}
#[test]
fn arrays_and_resource_envelopes_keep_real_offsets_and_original_rows() {
    let mut bytes = b"{\"records\":[".to_vec();
    let first = bytes.len() as u64;
    bytes.extend_from_slice(SIGNIN.trim_ascii_end());
    bytes.push(b',');
    let second = bytes.len() as u64;
    bytes.extend_from_slice(AUDIT.trim_ascii_end());
    bytes.extend_from_slice(b"]}");
    let (report, rows) = decode(&bytes);
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(
        (rows[0].origin().offset(), rows[1].origin().offset()),
        (Some(first), Some(second))
    );
    assert_eq!(
        EntraParser.detect("export.json", &bytes).unwrap().value(),
        98
    );
}
#[test]
fn a_bad_record_is_counted_and_cannot_hide_a_later_valid_row() {
    let mut bytes = b"{\"Type\":\"SigninLogs\",\"CreatedDateTime\":\"invalid\"}\n".to_vec();
    let offset = bytes.len() as u64;
    bytes.extend_from_slice(TABLE);
    let (report, rows) = decode(&bytes);
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(rows[0].origin().offset(), Some(offset));
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}
#[test]
fn decoder_passes_shared_purity_cancellation_and_taint_contract() {
    irmind_testkit::run_log_parser_contract(
        &EntraParser,
        &EntraSourceDecoder,
        "synthetic.ndjson",
        SIGNIN,
        1,
        None,
    )
    .unwrap();
}

struct RepeatedRows {
    row: Vec<u8>,
    repeats: usize,
    offset: usize,
}
impl std::io::Read for RepeatedRows {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < buffer.len() && self.repeats > 0 {
            let count = (buffer.len() - written).min(self.row.len() - self.offset);
            buffer[written..written + count]
                .copy_from_slice(&self.row[self.offset..self.offset + count]);
            written += count;
            self.offset += count;
            if self.offset == self.row.len() {
                self.offset = 0;
                self.repeats -= 1;
            }
        }
        Ok(written)
    }
}
#[test]
fn large_single_line_resource_envelopes_stream_every_row_with_real_offsets() {
    use std::io::Read as _;
    let entry = SIGNIN.trim_ascii_end();
    for mib in [5, 50, 200] {
        let records = mib * 1024 * 1024 / entry.len() + 1;
        let repeated = RepeatedRows {
            row: [entry, b","].concat(),
            repeats: records - 1,
            offset: 0,
        };
        let prefix = b"{\"records\":[";
        let mut input = std::io::Cursor::new(prefix)
            .chain(repeated)
            .chain(std::io::Cursor::new(entry))
            .chain(std::io::Cursor::new(b"]}"));
        let reference = SourceReferenceV1::file("synthetic.data").unwrap();
        let cancel = CancellationToken::new();
        let mut seen = 0;
        let report = EntraSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &reference,
                        evidence_hash: [7; 32],
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut input,
                },
                &mut |row| {
                    row.inspect(|record| {
                        assert_eq!(record.origin().record(), seen as u64);
                        assert_eq!(
                            record.origin().offset(),
                            Some((prefix.len() + seen * (entry.len() + 1)) as u64)
                        );
                        seen += 1;
                    });
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected), (records, 0));
        assert_eq!(seen, records);
    }
}
#[test]
fn malformed_jsonl_does_not_consume_a_later_export_record() {
    let bytes = [b"{broken}\n".as_slice(), SIGNIN].concat();
    let (report, rows) = decode(&bytes);
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(rows[0].origin().offset(), Some(9));
}
