#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn protocol_rejects_duplicates_unknown_fields_truncation_and_bad_counts() {
    for value in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":{"x":1,"x":2}}"#,
        br"{} trailing",
    ] {
        assert!(strict::decode(value).is_err());
    }
    let mut state = codec::State::new(69632);
    assert!(state.project_frame(br#"{"kind":"record","record_id":1,"offset":4608,"timestamp":"2026-11-01T00:00:00Z","event":{}}"#,&mut |_|Ok(true)).is_err());
    state
        .project_frame(
            br#"{"kind":"ready","protocol":"irmind-evtx-ndjson-v1","decoder":"0.15.1"}"#,
            &mut |_| Ok(true),
        )
        .unwrap();
    assert!(
        state
            .project_frame(
                br#"{"kind":"complete","accepted":1,"rejected":0}"#,
                &mut |_| Ok(true)
            )
            .is_err()
    );
    assert!(state.finish().is_err());
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
        cluster_context: None,
    });
    assert!(result.err().unwrap().to_string().contains("unavailable"));
    assert!(catalog.get_version("parser-evtx", VERSION).is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn initialization_errors_preserve_service_guidance_without_showing_source_paths() {
    let root = tempfile::tempdir().unwrap();
    let private_name = "synthetic-private-name-that-must-not-be-displayed";
    let parser = EvtxParser::new(&root.path().join(private_name), root.path());
    let reason = parser.unavailable_reason().unwrap();
    assert!(!reason.contains(private_name));
    let reason = super::initialization_error(&std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "EVTX requires running BFE and MpsSvc services with query and notification access",
    ))
    .to_string();
    assert!(reason.contains("running BFE and MpsSvc services"));
}
