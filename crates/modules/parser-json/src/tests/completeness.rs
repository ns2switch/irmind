use super::*;
use irmind_app::CancellationToken;
use std::io::{Cursor, Read};

const LIMIT: usize = 4 * 1024 * 1024;

fn run(source: &str, bytes: &[u8], direct: bool) -> (String, Vec<String>) {
    let mut events = Vec::new();
    let mut emit = |row: Tainted<GraphRecord>| {
        row.inspect(|row| events.push(row.event.clone()));
        Ok(())
    };
    let result = if direct {
        JsonParser
            .parse_reader(
                source,
                &mut Cursor::new(bytes),
                sha256(bytes),
                &CancellationToken::new(),
                &mut emit,
            )
            .map(|n| format!("direct accepted={n}"))
    } else {
        JsonParser
            .parse_reader_report(
                source,
                &mut Cursor::new(bytes),
                sha256(bytes),
                &CancellationToken::new(),
                &mut emit,
            )
            .map(|r| {
                format!(
                    "report accepted={} rejected={} samples={}",
                    r.accepted,
                    r.rejected,
                    r.samples.len()
                )
            })
    };
    (
        result.unwrap_or_else(|error| format!("ERR {error}")),
        events,
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
fn streamed_cloudtrail_5_50_200_mib_matches_document_reader() {
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
            let mut emit = |record: Tainted<GraphRecord>| {
                emitted += 1;
                record.inspect(|row| {
                    digest = sha256(&[digest.as_slice(), row.text.as_bytes()].concat());
                });
                Ok(())
            };
            if direct {
                let result = JsonParser.parse_reader(
                    "large.json",
                    &mut input,
                    [0; 32],
                    &CancellationToken::new(),
                    &mut emit,
                );
                assert_eq!(result.unwrap(), n);
                assert_eq!(emitted, n);
            } else {
                let result = JsonParser.parse_reader_report(
                    "large.json",
                    &mut input,
                    [0; 32],
                    &CancellationToken::new(),
                    &mut emit,
                );
                assert_eq!(result.unwrap().accepted, n);
                assert_eq!(emitted, n);
            }
            digests.push(digest);
        }
        assert_eq!(digests[0], digests[1]);
    }
}
