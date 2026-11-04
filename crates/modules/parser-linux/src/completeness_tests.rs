#![allow(clippy::unwrap_used, clippy::wildcard_imports)]
use crate::*;
use irmind_app::{CancellationToken, StreamingEventParser};
use std::io::{Cursor, Read};
#[test]
fn oversized_whitespace_prefixed_record_is_counted() {
    let bytes = include_bytes!("../../../testkit/fixtures/parser-linux/source/journal.jsonl");
    let first = bytes.split(|b| *b == b'\n').next().unwrap();
    let row = [first, b"\n"].concat();
    for mib in [5, 50, 200] {
        let mut input = Cursor::new(row.as_slice())
            .chain(std::io::repeat(b' ').take(mib * 1024 * 1024))
            .chain(Cursor::new(row.repeat(2)));
        let mut count = 0;
        let report = LinuxParser::default()
            .parse_reader_report(
                "synthetic.ndjson",
                &mut input,
                [0; 32],
                &CancellationToken::new(),
                &mut |_| {
                    count += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected, count), (2, 1, 2));
    }
}

struct CancelOnRead {
    token: CancellationToken,
    reads: usize,
}
impl Read for CancelOnRead {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        assert!(self.reads <= 2, "cancelled source must not keep draining");
        output.fill(b' ');
        self.token.cancel();
        Ok(output.len())
    }
}
#[test]
fn cancellation_during_a_newline_free_record_stops_the_reader() {
    let token = CancellationToken::new();
    let mut reader = CancelOnRead {
        token: token.clone(),
        reads: 0,
    };
    let result = LinuxParser::default().parse_reader_report(
        "synthetic.ndjson",
        &mut reader,
        [0; 32],
        &token,
        &mut |_| Ok(()),
    );
    assert!(matches!(result, Err(irmind_app::AppError::Cancelled)));
    assert_eq!(reader.reads, 1);
}
