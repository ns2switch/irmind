#![allow(clippy::unwrap_used, clippy::wildcard_imports)]
use irmind_app::CancellationToken;
use std::io::{Cursor, Read};
#[test]
fn oversized_whitespace_prefixed_record_is_counted() {
    let definition = r#"
version = 1
name = "synthetic-diagnostic"
description = "Synthetic-only diagnostic"
[input]
format = "ndjson"
[detect]
required_fields = ["/time"]
confidence = 70
[mapping]
time = "/time"
host = "/host"
action = "/action"
[timestamp]
format = "rfc3339"
default_timezone = "UTC"
"#;
    let pipeline = crate::pipeline::compile(definition).unwrap();
    let raw = br#"{"time":"2026-10-23T10:00:00Z","host":"synthetic","action":"login"}"#;
    let row = [raw.as_slice(), b"\n"].concat();
    for mib in [5, 50, 200] {
        let mut input = Cursor::new(row.as_slice())
            .chain(std::io::repeat(b' ').take(mib * 1024 * 1024))
            .chain(Cursor::new(row.repeat(2)));
        let mut count = 0;
        let report = irmind_testkit::decode_source(
            pipeline.decoder().as_ref(),
            "synthetic.ndjson",
            &mut input,
            [0; 32],
            &CancellationToken::new(),
            None,
            &mut |_| {
                count += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((report.accepted, report.rejected, count), (2, 1, 2));
    }
}

#[test]
fn csv_and_regex_count_an_oversized_whitespace_prefixed_record() {
    let examples = [
        (
            include_str!("../../../../docs/examples/parsers/access-csv.toml"),
            "time,host,user,source_ip,action,outcome\n",
            "2026-10-23T10:00:00Z,lab,alice,203.0.113.9,login,success\n",
        ),
        (
            include_str!("../../../../docs/examples/parsers/auth-regex.toml"),
            "",
            "2026-10-23T10:00:00Z host=lab user=alice src=203.0.113.9 action=login result=success\n",
        ),
    ];
    for (definition, header, row) in examples {
        let pipeline = crate::pipeline::compile(definition).unwrap();
        let mut input = Cursor::new(header.as_bytes())
            .chain(Cursor::new(row.as_bytes()))
            .chain(std::io::repeat(b' ').take(5 * 1024 * 1024))
            .chain(Cursor::new(row.repeat(2)));
        let report = irmind_testkit::decode_source(
            pipeline.decoder().as_ref(),
            "synthetic",
            &mut input,
            [0; 32],
            &CancellationToken::new(),
            None,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!((report.accepted, report.rejected), (2, 1));
    }
}
