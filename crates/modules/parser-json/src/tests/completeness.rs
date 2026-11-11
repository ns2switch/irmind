use super::*;
use irmind_app::CancellationToken;
use std::io::{Cursor, Read};

const LIMIT: usize = 4 * 1024 * 1024;

fn run(source: &str, bytes: &[u8], parallel: bool) -> (String, Vec<String>) {
    let mut events = Vec::new();
    let result = decode(source, &mut Cursor::new(bytes), parallel, &mut |row| {
        row.inspect(|row| {
            events.push(
                row.fields()
                    .field("eventName")
                    .and_then(irmind_domain::SourceValue::as_text)
                    .unwrap()
                    .to_owned(),
            );
        });
        Ok(())
    });
    (
        result.map_or_else(
            |error| format!("ERR {error}"),
            |r| {
                format!(
                    "report accepted={} rejected={} samples={}",
                    r.accepted,
                    r.rejected,
                    r.samples.len()
                )
            },
        ),
        events,
    )
}

fn decode(
    source: &str,
    reader: &mut dyn Read,
    parallel: bool,
    emit: &mut dyn FnMut(Tainted<irmind_domain::SourceRecordV1>) -> Result<(), AppError>,
) -> Result<irmind_app::ParseReport, AppError> {
    use irmind_app::{
        SourceDecoder,
        source_mapping::{DecodeBudget, DecodeInput, SourceInput, SourceMetadata},
    };
    let source = irmind_domain::SourceReferenceV1::file(source).unwrap();
    let cancel = CancellationToken::new();
    JsonSourceDecoder.decode_with_budget(
        DecodeInput::Reader(SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: [0; 32],
                time_context: None,
                cancel: &cancel,
            },
            reader,
        }),
        DecodeBudget::new(
            std::num::NonZeroUsize::new(if parallel { 4 } else { 1 }).unwrap(),
            8 * 1024 * 1024,
        ),
        emit,
    )
}

#[test]
fn large_document_sampling_preserves_every_byte() {
    let row = format!(
        "{{\"eventTime\":\"2026-11-01T00:00:00Z\",\"eventName\":\"Synthetic\",\"payload\":\"{}\"}}",
        "x".repeat(2048)
    );
    let mut one_line = format!(
        "{{\"Records\":[{}]}}",
        std::iter::repeat_n(row.as_str(), 2600)
            .collect::<Vec<_>>()
            .join(",")
    )
    .into_bytes();
    let (report, emitted) = run("cloudtrail.json", &one_line, false);
    let (_direct, complete) = run("cloudtrail.json", &one_line, true);
    assert_eq!(report, "report accepted=2600 rejected=0 samples=0");
    assert_eq!(emitted, complete);
    assert_eq!(complete.len(), 2600);
    one_line.clear();

    let first = br#"{"Records":[{"eventName":"First"}]}"#;
    let last = br#"{"Records":[{"eventName":"Last"}]}"#;
    let mut concatenated = first.to_vec();
    concatenated.resize(LIMIT + 1024, b' ');
    concatenated.extend_from_slice(last);
    let (report, actual) = run("stream.json", &concatenated, false);
    let (_direct, expected) = run("stream.json", &concatenated, true);
    assert_eq!(actual, expected);
    assert_eq!(expected, ["First", "Last"]);
    assert_eq!(report, "report accepted=2 rejected=0 samples=0");

    let mut multiline = br#"{"Records":[{"eventName":"First"},"#.to_vec();
    multiline.resize(LIMIT + 1, b' ');
    multiline.extend_from_slice(b"{\"eventName\":\"Hidden\"},\n{\"eventName\":\"Last\"}]}");
    let (report, actual) = run("cloudtrail.json", &multiline, false);
    let (_direct, expected) = run("cloudtrail.json", &multiline, true);
    assert_eq!(actual, expected);
    assert_eq!(expected, ["First", "Hidden", "Last"]);
    assert_eq!(report, "report accepted=3 rejected=0 samples=0");

    let mut prefix_only = first.to_vec();
    prefix_only.resize(LIMIT + 1024, b' ');
    let (_report, actual) = run("padded.json", &prefix_only, false);
    assert_eq!(actual, ["First"]);
}

struct Repeated<'a> {
    row: &'a [u8],
    remaining: usize,
    offset: usize,
}
impl Read for Repeated<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut filled = 0;
        while filled < out.len() && self.remaining > 0 {
            let n = (out.len() - filled).min(self.row.len() - self.offset);
            out[filled..filled + n].copy_from_slice(&self.row[self.offset..self.offset + n]);
            filled += n;
            self.offset += n;
            if self.offset == self.row.len() {
                self.offset = 0;
                self.remaining -= 1;
            }
        }
        Ok(filled)
    }
}

#[test]
fn streamed_cloudtrail_5_50_200_mib_preserves_fields_offsets_and_parallel_bytes() {
    let row = format!(
        "{{\"eventTime\":\"2026-11-01T00:00:00Z\",\"eventName\":\"Synthetic\",\"payload\":\"{}\"}},",
        "x".repeat(2048)
    );
    let last = &row[..row.len() - 1];
    for mib in [5, 50, 200] {
        let n = (mib * 1024 * 1024) / row.len() + 1;
        let mut digests = Vec::new();
        for direct in [false, true] {
            let mut input = Cursor::new(b"{\"Records\":[")
                .chain(Repeated {
                    row: row.as_bytes(),
                    remaining: n - 1,
                    offset: 0,
                })
                .chain(Cursor::new(format!("{last}]}}")));
            let mut emitted = 0;
            let mut digest = [0u8; 32];
            let expected = irmind_app::source_mapping::json::decode_json_fields(
                last.as_bytes(),
                irmind_app::source_mapping::json::SourceJsonLimits::default(),
            )
            .unwrap();
            let mut emit = |record: Tainted<irmind_domain::SourceRecordV1>| {
                record.inspect(|record| {
                    assert_eq!(record.fields(), &expected);
                    assert_eq!(record.origin().record(), emitted as u64);
                    assert_eq!(
                        record.origin().offset(),
                        Some((b"{\"Records\":[".len() + emitted * row.len()) as u64)
                    );
                    let mut canonical = Vec::new();
                    record.feed_canonical(&mut |part| canonical.extend_from_slice(part));
                    digest = sha256(&[digest.as_slice(), &canonical].concat());
                });
                emitted += 1;
                Ok(())
            };
            let report = decode("large.json", &mut input, direct, &mut emit).unwrap();
            assert_eq!((report.accepted, report.rejected, emitted), (n, 0, n));
            digests.push(digest);
        }
        assert_eq!(digests[0], digests[1]);
    }
}
