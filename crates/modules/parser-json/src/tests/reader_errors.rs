#![allow(clippy::panic)]
use super::*;
use irmind_app::CancellationToken;
use std::io::{self, Cursor, Read};

struct FailingEnd(Cursor<&'static [u8]>);
impl Read for FailingEnd {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(bytes)?;
        if n == 0 {
            Err(io::Error::other("synthetic source read failure"))
        } else {
            Ok(n)
        }
    }
}

#[test]
fn source_read_error_after_complete_root_is_not_a_successful_report() {
    let mut source = FailingEnd(Cursor::new(br#"{"Records":[{"eventName":"A"}]}"#));
    assert!(
        JsonParser
            .parse_reader_report(
                "source.json",
                &mut source,
                [0; 32],
                &CancellationToken::new(),
                &mut |_| Ok(())
            )
            .is_err()
    );
}

#[test]
fn wrapped_array_does_not_disable_limits_on_later_metadata() {
    let text = format!(
        "{{\"Records\":[],\"metadata\":\"{}\"}}",
        "x".repeat(4 * 1024 * 1024)
    );
    let result = JsonParser.parse_reader_report(
        "source.json",
        &mut text.as_bytes(),
        [0; 32],
        &CancellationToken::new(),
        &mut |_| Ok(()),
    );
    assert!(result.is_err());
}

#[test]
fn explicitly_line_delimited_json_rejects_whitespace_prefix_without_losing_next_row() {
    let row = b"{\"eventName\":\"Visible\"}\n";
    let mut input = io::repeat(b' ')
        .take(5 * 1024 * 1024)
        .chain(Cursor::new(row.repeat(2)));
    let report = JsonParser
        .parse_reader_report(
            "source.ndjson",
            &mut input,
            [0; 32],
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(
        (report.accepted, report.rejected, report.samples.len()),
        (1, 1, 1)
    );
}

#[test]
fn cancelled_large_document_probe_does_not_emit_or_report_success() {
    let token = CancellationToken::new();
    token.cancel();
    let mut input = io::repeat(b' ').take(200 * 1024 * 1024);
    assert!(matches!(
        JsonParser.parse_reader_report(
            "source.json",
            &mut input,
            [0; 32],
            &token,
            &mut |_| panic!("cancelled input must not emit")
        ),
        Err(AppError::Cancelled)
    ));
}

#[test]
fn catalog_does_not_reinterpret_retired_parser_versions() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(JsonParser), &ModuleConfig::new())
        .unwrap();
    let catalog = registry.parser_catalog();
    assert!(catalog.get_version("parser-json", "json-stream-v3").is_ok());
    let Err(error) = catalog.get_version("parser-json", "json-stream-v2") else {
        panic!("retired reader must not alias the current parser");
    };
    assert!(error.to_string().contains("create a new case"));
}
