use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder, StreamingEventParser,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::EventOutcome;
const INPUT:&[u8]=b"2026-11-01T00:00:00Z synthetic-host useradd[42]: new user: name=synthetic-user, UID=1001\n2026-11-01T00:00:01Z synthetic-host usermod[42]: change user 'synthetic-user' shell\n2026-11-01T00:00:02Z synthetic-host CRON[42]: (synthetic-user) CMD (/usr/bin/true)\n2026-11-01T00:00:03Z synthetic-host crond[42]: (synthetic-user) CMD (/usr/bin/true)\n2026-11-01T00:00:04Z synthetic-host cron[42]: (synthetic-user) CMD (/usr/bin/true)\n";
#[test]
fn all_unclassified_auth_datasets_pass_the_shared_contract() {
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_linux::LinuxSourceDecoder),
        Arc::new(AuthExtractionMapping::new().unwrap()),
        "synthetic.log",
        INPUT,
        5,
    )
    .unwrap();
}
#[test]
fn account_management_cron_and_reused_pids_keep_legacy_search_identities_without_roles() {
    let mut legacy = Vec::new();
    let mut sources = Vec::new();
    let cancel = CancellationToken::new();
    irmind_mod_parser_linux::LinuxParser::default()
        .parse_indexed_reader_report(
            "synthetic.log",
            &mut std::io::Cursor::new(INPUT),
            irmind_app::sha256(INPUT),
            &cancel,
            &mut |row| {
                row.inspect(|r| legacy.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    let reference = SourceReferenceV1::file("synthetic.log").unwrap();
    irmind_mod_parser_linux::LinuxSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(INPUT),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(INPUT),
            },
            &mut |row| {
                row.inspect(|r| sources.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    let mapper = AuthExtractionMapping::new().unwrap();
    assert_eq!(sources.len(), 5);
    for (source, old) in sources.iter().zip(legacy) {
        let out = mapper.map(source).unwrap();
        assert_eq!(out.record().indexed.record.event, old.record.event);
        assert_eq!(out.record().indexed.record.entities, old.record.entities);
        assert_eq!(out.record().indexed.time, old.time);
        assert!(out.record().common.observations().values().is_empty());
        assert_eq!(out.record().common.event().outcome(), EventOutcome::Unknown);
    }
}
