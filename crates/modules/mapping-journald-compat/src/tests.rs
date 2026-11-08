use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder, StreamingEventParser,
    source_mapping::{SourceInput, SourceMetadata},
};
#[test]
fn extracted_identity_and_projection_match_the_frozen_journald_baseline() {
    for epoch in ["1794096000000000", "1794096000123000", "1794096000123456"] {
        let bytes = format!(
            "{{\"__REALTIME_TIMESTAMP\":\"{epoch}\",\"_HOSTNAME\":\"host-01\",\"_UID\":\"1000\",\"_PID\":\"17\",\"_EXE\":\"/usr/bin/synthetic\",\"_CMDLINE\":\"synthetic --example\",\"MESSAGE\":\"original untrusted message\"}}\n"
        );
        let bytes = bytes.as_bytes();
        let cancel = CancellationToken::new();
        let hash = irmind_app::sha256(bytes);
        let mut expected = Vec::new();
        irmind_mod_parser_linux::LinuxParser::default()
            .parse_reader_report(
                "journal.jsonl",
                &mut std::io::Cursor::new(bytes),
                hash,
                &cancel,
                &mut |r| {
                    r.inspect(|record| expected.push(record.clone()));
                    Ok(())
                },
            )
            .unwrap();
        let mapper = JournaldCompatibilityMapping::new().unwrap();
        let mut actual = Vec::new();
        irmind_mod_parser_linux::JournalSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &irmind_domain::SourceReferenceV1::file("journal.jsonl").unwrap(),
                        evidence_hash: hash,
                        time_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut std::io::Cursor::new(bytes),
                },
                &mut |r| {
                    r.inspect(|source| actual.push(mapper.map(source).unwrap()));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            let record = &actual.record().indexed.record;
            assert_eq!(record.entities, expected.entities);
            assert_eq!(record.text, expected.text);
            assert_eq!(record.at, expected.at);
            assert_eq!(
                actual.record().common.event(),
                &irmind_domain::EventHeaderV1::default()
            );
        }
    }
}
