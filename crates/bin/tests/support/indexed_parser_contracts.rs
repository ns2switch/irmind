use super::*;
use irmind_app::{IndexedGraphRecord, IndexedTime};
use irmind_domain::TimePrecision;

fn indexed(parser: &dyn StreamingEventParser, bytes: &[u8]) -> Vec<IndexedGraphRecord> {
    let mut output = Vec::new();
    let report = parser
        .parse_indexed_reader_report(
            "synthetic",
            &mut std::io::Cursor::new(bytes),
            sha256(bytes),
            &CancellationToken::new(),
            &mut |row| {
                assert_eq!(row.provenance().evidence_hash(), &sha256(bytes));
                row.inspect(|r| output.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        report.rejected,
        0,
        "{}: {:?}",
        parser.parser_name(),
        report.samples
    );
    assert!(!output.is_empty());
    output
}
#[test]
fn native_indexed_callbacks_preserve_normalized_output_and_taint() {
    for (name, parser, bytes) in parsers() {
        let mut legacy = Vec::new();
        parser
            .parse_reader_report(
                "synthetic",
                &mut std::io::Cursor::new(bytes),
                sha256(bytes),
                &CancellationToken::new(),
                &mut |row| {
                    legacy.push(row);
                    Ok(())
                },
            )
            .unwrap();
        let mut precise = Vec::new();
        let report = parser
            .parse_indexed_reader_report(
                "synthetic",
                &mut std::io::Cursor::new(bytes),
                sha256(bytes),
                &CancellationToken::new(),
                &mut |row| {
                    precise.push(row);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(report.rejected, 0, "{name}");
        assert_eq!(precise.len(), legacy.len(), "{name}");
        for (old, new) in legacy.iter().zip(&precise) {
            assert_eq!(old.provenance(), new.provenance(), "{name}");
            old.inspect(|a| {
                new.inspect(|b| {
                    assert_eq!(a, &b.record, "{name}");
                    assert_eq!(b.source_offset, None);
                });
            });
        }
    }
}
#[test]
fn native_precision_preserves_zero_fraction_digits_instead_of_guessing() {
    for (name, parser, bytes) in parsers() {
        if !matches!(
            name,
            "json" | "ecs" | "ocsf" | "velociraptor" | "chainsaw" | "plaso"
        ) {
            continue;
        }
        let raw = std::str::from_utf8(bytes).unwrap();
        let changed = raw
            .replace("2026-10-23T12:00:00Z", "2026-10-23T12:00:00.000000100Z")
            .replace("2026-01-02T03:04:05Z", "2026-01-02T03:04:05.000000Z")
            .replace("2026-10-23T12:01:00Z", "2026-10-23T12:01:00.000000Z");
        let rows = indexed(parser.as_ref(), changed.as_bytes());
        let time = rows[0].time.unwrap();
        match name {
            "ocsf" => assert_eq!(time.precision(), TimePrecision::Millisecond),
            "plaso" | "ecs" | "chainsaw" => {
                assert_eq!(time.precision(), TimePrecision::Microsecond);
            }
            "velociraptor" => {
                assert_eq!(time.precision(), TimePrecision::Nanosecond);
                assert_eq!(time.instant().submicro_nanos(), 100);
            }
            _ => {}
        }
    }
}
#[cfg(all(feature = "parser-linux", feature = "parser-syslog"))]
#[test]
fn linux_and_syslog_recover_precision_from_original_records() {
    let linux = irmind_mod_parser_linux::LinuxParser::default();
    let journal = indexed(
        &linux,
        include_bytes!("../../../testkit/fixtures/parser-linux/source/journal.jsonl"),
    );
    assert_eq!(
        journal[0].time.unwrap().instant().unix_micros(),
        1_793_494_800_123_456
    );
    assert_eq!(
        journal[0].time.unwrap().precision(),
        TimePrecision::Microsecond
    );
    let audit = indexed(
        &linux,
        include_bytes!("../../../testkit/fixtures/parser-linux/source/audit.log"),
    );
    assert_eq!(
        audit[0].time.unwrap().instant().unix_micros(),
        1_793_494_800_123_456
    );
    let syslog = irmind_mod_parser_syslog::SyslogParser::default();
    let rows = indexed(
        &syslog,
        b"<34>1 2026-11-01T00:02:03.123456700Z lab app 42 X - synthetic\n",
    );
    let time = rows[0].time.unwrap();
    assert_eq!(
        time,
        IndexedTime::from_rfc3339("2026-11-01T00:02:03.123456700Z", false).unwrap()
    );
}
