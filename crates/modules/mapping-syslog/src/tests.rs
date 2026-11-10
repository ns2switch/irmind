use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder, StreamingEventParser,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{EventOutcome, IndexedTime};
const MODERN:&[u8]=b"<34>1 2026-11-01T00:00:00.123456789Z synthetic-host app 42 ID47 - synthetic message\n<34>1 2026-11-01T00:00:01Z synthetic-host app 43 ID48 - second synthetic message\n";
fn sources(bytes: &[u8]) -> (irmind_app::ParseReport, Vec<SourceRecordV1>) {
    let source = SourceReferenceV1::file("synthetic.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = irmind_mod_parser_syslog::SyslogSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |row| {
                row.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}
#[test]
fn shared_contract_covers_determinism_parallelism_taint_and_cancellation() {
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_syslog::SyslogSourceDecoder),
        Arc::new(SyslogExtractionMapping::new().unwrap()),
        "synthetic.log",
        MODERN,
        2,
    )
    .unwrap();
}
#[test]
fn old_search_aliases_survive_without_inferring_categories_or_roles() {
    let (_, rows) = sources(MODERN);
    let mut old = Vec::new();
    irmind_mod_parser_syslog::SyslogParser::default()
        .parse_indexed_reader_report(
            "synthetic.log",
            &mut std::io::Cursor::new(MODERN),
            irmind_app::sha256(MODERN),
            &CancellationToken::new(),
            &mut |row| {
                row.inspect(|r| old.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    let mapper = SyslogExtractionMapping::new().unwrap();
    for (source, old) in rows.iter().zip(old) {
        let out = mapper.map(source).unwrap();
        assert_eq!(out.record().indexed.record.entities, old.record.entities);
        assert_eq!(out.record().indexed.record.event, old.record.event);
        assert_eq!(out.record().indexed.time, old.time);
        assert_eq!(out.record().common.event().outcome(), EventOutcome::Unknown);
        assert!(out.record().common.observations().values().is_empty());
    }
}
#[test]
fn missing_timestamp_and_nil_headers_remain_absent() {
    let (_, rows) = sources(b"<34>1 - - - - - - synthetic only\n");
    let mapped = SyslogExtractionMapping::new()
        .unwrap()
        .map(&rows[0])
        .unwrap();
    assert!(mapped.record().indexed.time.is_none());
    assert!(mapped.record().indexed.record.entities.is_empty());
    assert_eq!(mapped.record().indexed.record.event, "syslog");
    assert!(
        rows[0]
            .fields()
            .field("timestamp")
            .unwrap()
            .as_text()
            .is_some()
    );
}
#[test]
fn numeric_offset_is_preserved_as_an_instant_not_a_wall_clock_guess() {
    let (_, rows) = sources(b"<34>1 2026-11-01T01:02:03.123456+01:00 host app 42 - - synthetic\n");
    assert_eq!(
        rows[0].timestamp(),
        Some(IndexedTime::from_rfc3339("2026-11-01T00:02:03.123456Z", false).unwrap())
    );
}
