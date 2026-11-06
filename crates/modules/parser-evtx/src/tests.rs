#![allow(clippy::unwrap_used)]
use super::*;
use serde_json::json;
#[test]
fn protocol_rejects_duplicates_unknown_fields_truncation_and_bad_counts() {
    for value in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":{"x":1,"x":2}}"#,
        br"{} trailing",
    ] {
        assert!(strict::decode(value).is_err());
    }
    let mut state = codec::State::new("source.evtx", [1; 32], 69632);
    assert!(state.frame(br#"{"kind":"record","record_id":1,"offset":4608,"timestamp":"2026-11-01T00:00:00Z","event":{}}"#,&mut |_|Ok(())).is_err());
    state
        .frame(
            br#"{"kind":"ready","protocol":"irmind-evtx-ndjson-v1","decoder":"0.15.1"}"#,
            &mut |_| Ok(()),
        )
        .unwrap();
    assert!(
        state
            .frame(
                br#"{"kind":"complete","accepted":1,"rejected":0}"#,
                &mut |_| Ok(())
            )
            .is_err()
    );
    assert!(state.finish().is_err());
}
#[test]
fn normalized_records_are_tainted_precise_and_canonical() {
    let bytes=br#"{"Event":{"System":{"EventID":4624,"Computer":"synthetic-endpoint","Channel":"Security"},"EventData":{"TargetUserName":"synthetic-user","IpAddress":"203.0.113.77"}}}"#;
    let row = normalize::record(
        "source.evtx",
        [1; 32],
        0,
        1,
        4608,
        "2026-11-01T00:00:00.0000007Z",
        &serde_json::from_slice(bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(
        row.provenance().parser_location().unwrap().byte_offset(),
        4608
    );
    row.inspect(|r| {
        assert_eq!(r.time.as_ref().unwrap().instant().submicro_nanos(), 700);
        assert_eq!(r.record.event, "logon_success");
        assert!(
            r.record
                .entities
                .contains(&("host".into(), "synthetic-endpoint".into()))
        );
    });
}
#[test]
fn all_required_event_ids_have_explicit_mappings() {
    for (channel, ids) in [
        (
            "Security",
            vec![
                4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 4768, 4769, 4776, 1102,
            ],
        ),
        ("System", vec![7045]),
        ("PowerShell", vec![4103, 4104]),
        ("Sysmon", vec![1, 3, 7, 8, 10, 11, 12, 13, 22, 23]),
    ] {
        for id in ids {
            let row=normalize::record("source.evtx",[0;32],0,1,4608,"2026-11-01T00:00:00Z",&json!({"Event":{"System":{"EventID":id,"Channel":channel,"Computer":"host"},"EventData":{}}})).unwrap();
            row.inspect(|r| assert_ne!(r.record.event, "windows_event"));
        }
    }
}
#[test]
fn detection_is_content_based_and_bounded() {
    assert!(codec::detect(include_bytes!(
        "../../../testkit/fixtures/parser-evtx/source/Security.evtx"
    )));
    assert!(!codec::detect(b"ElfFile\0"));
    assert!(!codec::detect(b"{\"event\":\"evtx\"}"));
}

#[test]
fn unavailable_decoder_is_recognized_but_cannot_be_selected_or_rebuilt() {
    use irmind_app::modules::{ParserChoice, ParserSelectionRequest};
    let root = tempfile::tempdir().unwrap();
    let parser = EvtxParser::new(&root.path().join("missing-helper"), root.path());
    let reason = parser.unavailable_reason().unwrap().to_owned();
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(parser), &ModuleConfig::new())
        .unwrap();
    registry
        .mark_parser_unavailable("parser-evtx", reason)
        .unwrap();
    let sample =
        &include_bytes!("../../../testkit/fixtures/parser-evtx/source/Security.evtx")[..65536];
    let catalog = registry.parser_catalog();
    assert!(matches!(
        catalog.detect("arbitrary-name.bin", sample),
        ParserChoice::Auto(_)
    ));
    assert!(catalog.available().is_empty());
    let result = catalog.select_source(ParserSelectionRequest {
        source: "arbitrary-name.bin",
        sample,
        parser_override: None,
        forced: false,
        time_context: None,
    });
    assert!(result.err().unwrap().to_string().contains("unavailable"));
    assert!(catalog.get_version("parser-evtx", VERSION).is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
