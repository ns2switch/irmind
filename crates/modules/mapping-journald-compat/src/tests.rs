use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
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
        let mapper = JournaldCompatibilityMapping::new().unwrap();
        let mut actual = Vec::new();
        irmind_mod_parser_linux::LinuxSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &irmind_domain::SourceReferenceV1::file("journal.jsonl").unwrap(),
                        evidence_hash: hash,
                        time_context: None,
                        cluster_context: None,
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
        assert_eq!(actual.len(), 1);
        for actual in &actual {
            let record = &actual.record().indexed.record;
            assert!(record.entities.contains(&("host".into(), "host-01".into())));
            assert!(
                record
                    .entities
                    .contains(&("command_line".into(), "synthetic --example".into()))
            );
            assert!(record.text.contains(epoch));
            assert_eq!(
                actual
                    .record()
                    .indexed
                    .time
                    .unwrap()
                    .instant()
                    .unix_micros()
                    .to_string(),
                epoch
            );
            assert_eq!(
                actual.record().common.event(),
                &irmind_domain::EventHeaderV1::default()
            );
        }
    }
}

#[test]
fn shared_source_mapping_contract() {
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_linux::LinuxSourceDecoder), Arc::new(JournaldCompatibilityMapping::new().unwrap()),
        "journal.json", br#"{"__REALTIME_TIMESTAMP":"1793102400123456","_HOSTNAME":"synthetic","MESSAGE":"example"}"#, 1,
    ).unwrap();
}
