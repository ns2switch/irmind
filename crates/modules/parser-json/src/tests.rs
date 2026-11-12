use super::*;
use irmind_app::sha256;
use irmind_domain::Tainted;

#[test]
fn detection_accepts_known_cloud_json_and_requests_review_for_generic_json() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(JsonParser), &ModuleConfig::new())
        .unwrap();
    let known = include_str!("../tests/fixtures/hunteval-aws-iam-001.json");
    assert!(matches!(
        registry.detect_parser("events.json", known.as_bytes()),
        irmind_app::modules::ParserChoice::Auto(candidate) if candidate.id == "parser-json"
    ));
    assert!(matches!(
        registry.detect_parser("generic.json", br#"{"hello":"world"}"#),
        irmind_app::modules::ParserChoice::NeedsAnalyst(_)
    ));
    assert!(matches!(
        registry.detect_parser("system.evtx", b"ElfFile"),
        irmind_app::modules::ParserChoice::Unsupported
    ));
}

#[test]
fn streamed_file_records_keep_parser_and_byte_offset_provenance() {
    let bytes = b"{\"eventName\":\"First\"}\n{\"eventName\":\"Second\"}\n";
    let mut offsets = Vec::new();
    irmind_testkit::decode_source(
        &JsonSourceDecoder,
        "events.jsonl",
        &mut bytes.as_slice(),
        sha256(bytes),
        &irmind_app::CancellationToken::new(),
        None,
        &mut |record| {
            let location = record.provenance().parser_location().unwrap();
            assert_eq!(location.source(), "events.jsonl");
            assert_eq!(location.parser_id(), "parser-json");
            offsets.push(location.byte_offset());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(offsets, [0, 22]);

    let array = b"[{\"eventName\":\"A\"},{\"eventName\":\"B\"}]";
    offsets.clear();
    irmind_testkit::decode_source(
        &JsonSourceDecoder,
        "array.json",
        &mut array.as_slice(),
        sha256(array),
        &irmind_app::CancellationToken::new(),
        None,
        &mut |record| {
            offsets.push(record.provenance().parser_location().unwrap().byte_offset());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(offsets, [1, 19]);
}

#[test]
fn malformed_jsonl_row_is_counted_and_later_row_survives() {
    let bytes = b"{\"eventName\":\"First\"}\n{broken\n{\"eventName\":\"Last\"}\n";
    let mut names = Vec::new();
    let report = irmind_testkit::decode_source(
        &JsonSourceDecoder,
        "events.jsonl",
        &mut bytes.as_slice(),
        sha256(bytes),
        &irmind_app::CancellationToken::new(),
        None,
        &mut |record| {
            record.inspect(|value| {
                names.push(
                    value
                        .fields()
                        .field("eventName")
                        .and_then(irmind_domain::SourceValue::as_text)
                        .unwrap()
                        .to_owned(),
                );
            });
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(names, ["First", "Last"]);
    assert_eq!(report.accepted, 2);
    assert_eq!(report.rejected, 1);
    assert_eq!(report.samples.len(), 1);
    assert!(report.samples[0].contains("broken"));
}

#[test]
fn streaming_reader_recognizes_exported_cloud_formats() {
    let cases = [
        (
            "cloudtrail.json",
            r#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole"}]}"#,
            "AssumeRole",
        ),
        (
            "gcp.jsonl",
            r#"{"timestamp":"2026-10-23T12:00:00Z","protoPayload":{"methodName":"google.iam.admin.v1.CreateServiceAccount","authenticationInfo":{"principalEmail":"analyst@example.invalid"}},"resource":{"labels":{"project_id":"example-project"}}}"#,
            "google.iam.admin.v1.CreateServiceAccount",
        ),
        (
            "activity.json",
            r#"{"records":[{"eventTimestamp":"2026-10-23T12:00:00Z","operationName":{"value":"Microsoft.Compute/virtualMachines/write"},"subscriptionId":"00000000-0000-0000-0000-000000000000"}]}"#,
            "Microsoft.Compute/virtualMachines/write",
        ),
        (
            "entra.jsonl",
            r#"{"createdDateTime":"2026-10-23T12:00:00Z","operationName":"Sign-in activity","userPrincipalName":"analyst@example.invalid","ipAddress":"203.0.113.17"}"#,
            "Sign-in activity",
        ),
    ];
    for (source, json, event) in cases {
        let mut parsed = Vec::new();
        let count = irmind_testkit::decode_source(
            &JsonSourceDecoder,
            source,
            &mut json.as_bytes(),
            sha256(json.as_bytes()),
            &irmind_app::CancellationToken::new(),
            None,
            &mut |record| {
                record.inspect(|value| {
                    parsed.push((
                        value.timestamp().unwrap().to_rfc3339(),
                        irmind_app::source_mapping::json::render_source_fields(value.fields())
                            .unwrap(),
                    ));
                });
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count.accepted, 1, "{source}");
        assert_eq!(parsed[0].0, "2026-10-23T12:00:00Z", "{source}");
        assert!(parsed[0].1.contains(event), "{source}");
    }
}

#[test]
fn streaming_reader_rejects_oversized_record_before_emitting_it() {
    let long_value = "x".repeat(4 * 1024 * 1024);
    let json = format!("{{\"message\":\"{long_value}\"}}");
    let mut emitted = 0;
    let result = irmind_testkit::decode_source(
        &JsonSourceDecoder,
        "oversized.json",
        &mut json.as_bytes(),
        sha256(json.as_bytes()),
        &irmind_app::CancellationToken::new(),
        None,
        &mut |_| {
            emitted += 1;
            Ok(())
        },
    );
    let report = result.unwrap();
    assert_eq!((report.accepted, report.rejected), (0, 1));
    assert_eq!(emitted, 0);
}

mod order;

mod completeness;

mod reader_errors;

#[test]
fn source_decoder_rejects_excessive_json_depth_without_emitting() {
    let input = format!("{}0{}", "[".repeat(130), "]".repeat(130));
    let mut emitted = 0;
    let result = irmind_testkit::decode_source(
        &JsonSourceDecoder,
        "nested.json",
        &mut input.as_bytes(),
        [0; 32],
        &irmind_app::CancellationToken::new(),
        None,
        &mut |_| {
            emitted += 1;
            Ok(())
        },
    );
    let report = result.unwrap();
    assert_eq!((report.accepted, report.rejected), (0, 1));
    assert!(!report.samples.is_empty());
    assert_eq!(emitted, 0);
}
