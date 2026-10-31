use super::*;

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
fn parses_attributed_hunteval_aws_episode_without_private_answers() {
    let source = include_str!("../tests/fixtures/hunteval-aws-iam-001.json");
    let records = JsonParser
        .parse("hunteval/aws-iam-001/source/events.json", source.as_bytes())
        .unwrap();
    assert_eq!(records.len(), 10);
    records[3].inspect(|record| {
        assert_eq!(record.at, "2026-01-10T10:30:00Z");
        assert_eq!(record.event, "AttachUserPolicy");
        for (kind, value) in [
            ("principal", "arn:aws:iam::111122223333:user/alex"),
            ("account", "111122223333"),
            ("ip", "203.0.113.77"),
            ("user_agent", "aws-cli/2.15"),
        ] {
            assert!(record.entities.contains(&(kind.into(), value.into())));
        }
        assert!(
            record
                .entities
                .iter()
                .any(|(kind, value)| { kind == "event_id" && value.ends_with(":evt-0004") })
        );
        assert_eq!(record.relations.len(), 5);
        assert!(!record.text.contains("malicious_event_ids"));
        assert!(!record.text.contains("acceptable_conclusions"));
    });
}

#[test]
fn normalized_aws_azure_gcp_events_extract_the_same_typed_entities() {
    for (provider, principal, resource) in [
        (
            "aws",
            "arn:aws:iam::123456789012:user/alice",
            "aws:resource:admin",
        ),
        ("azure", "suspected-identity", "azure:resource:admin"),
        ("gcp", "suspected-identity", "gcp:resource:admin"),
    ] {
        let source = serde_json::json!([{
            "event_id": "evt-0001", "event_time": "2026-01-01T00:00:00Z",
            "account_id": format!("{provider}-account"), "principal": principal,
            "event_name": "GrantPrivilege", "resource": resource,
            "source_ip": "203.0.113.77", "user_agent": "hunteval-test/1.0",
            "provider": provider
        }]);
        let records = JsonParser
            .parse("normalized.json", source.to_string().as_bytes())
            .unwrap();
        records[0].inspect(|record| {
            for (kind, value) in [
                ("principal", principal),
                ("resource", resource),
                ("ip", "203.0.113.77"),
                ("user_agent", "hunteval-test/1.0"),
            ] {
                assert!(record.entities.contains(&(kind.into(), value.into())));
            }
        });
    }
}

#[test]
fn malformed_normalized_event_fails_closed() {
    let record = serde_json::json!({
        "event_id": "evt-0001", "event_time": "2026-01-01T00:00:00Z",
        "account_id": "test", "principal": "suspected-identity",
        "event_name": "GrantPrivilege", "resource": "gcp:resource:admin",
        "source_ip": "not-an-ip", "user_agent": "hunteval-test/1.0", "provider": "gcp"
    });
    assert!(
        JsonParser
            .parse("normalized.json", record.to_string().as_bytes())
            .is_err()
    );
}

#[test]
fn indexes_cloudtrail_record() {
    let bytes = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","sourceIPAddress":"203.0.113.8","userIdentity":{"arn":"arn:aws:iam::123456789012:role/Admin"}}]}"#;
    let records = JsonParser.parse("cloudtrail.json", bytes).unwrap();
    assert_eq!(records.len(), 1);
    records[0].inspect(|record| {
        assert!(
            record
                .entities
                .contains(&("ip".into(), "203.0.113.8".into()))
        );
        assert!(
            record
                .entities
                .contains(&("role".into(), "arn:aws:iam::123456789012:role/Admin".into()))
        );
        assert!(record.text.contains("AssumeRole"));
    });
}

#[test]
fn extracts_assume_role_relation_from_cloudtrail_fields() {
    let bytes = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/Admin"}}]}"#;
    let records = JsonParser.parse("cloudtrail.json", bytes).unwrap();
    records[0].inspect(|record| {
        assert_eq!(record.relations.len(), 1);
        assert_eq!(record.relations[0].relation, "assumed_role");
        assert_eq!(record.relations[0].from_kind, "identity");
        assert_eq!(record.relations[0].to_kind, "role");
    });
}

#[test]
fn links_cloudtrail_origin_session_and_access_keys() {
    let bytes = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"GetObject","sourceIPAddress":"198.51.100.9","userIdentity":{"arn":"arn:aws:sts::123456789012:assumed-role/Analyst/session","accessKeyId":"ASIAABCDEFGHIJKLMNOP","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::123456789012:role/Analyst"}}}},{"eventTime":"2026-10-23T12:01:00Z","eventName":"CreateAccessKey","requestParameters":{"userName":"alice"},"responseElements":{"accessKey":{"accessKeyId":"AKIAABCDEFGHIJKLMNOP"}}}]}"#;
    let records = JsonParser.parse("cloudtrail.json", bytes).unwrap();
    assert_eq!(records.len(), 2);
    records[0].inspect(|record| {
        assert_eq!(record.relations.len(), 3);
        assert!(
            record
                .relations
                .iter()
                .any(|relation| relation.relation == "observed_from_ip"
                    && relation.to_value == "198.51.100.9")
        );
        assert!(
            record
                .relations
                .iter()
                .any(|relation| relation.relation == "issued_session"
                    && relation.from_kind == "role")
        );
        assert!(record.relations.iter().any(
                |relation| relation.relation == "used_access_key" && relation.to_kind == "key"
            ));
    });
    records[1].inspect(|record| assert_eq!(record.relations[0].relation, "created_access_key"));
}

#[test]
fn remote_envelopes_become_separate_timeline_records() {
    let cloud = br#"{"events":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole"},{"eventTime":"2026-10-23T13:00:00Z","eventName":"GetObject"}]}"#;
    let records = JsonParser.parse("cloud_audit_events:aws", cloud).unwrap();
    assert_eq!(records.len(), 2);
    records[1].inspect(|record| assert_eq!(record.event, "GetObject"));
    let splunk = br#"{"result":{"_raw":"{\"eventTime\":\"2026-10-23T12:00:00Z\",\"eventName\":\"AssumeRole\"}"}}"#;
    let records = JsonParser.parse("siem_search:splunk", splunk).unwrap();
    assert_eq!(records.len(), 1);
    records[0].inspect(|record| assert_eq!(record.event, "AssumeRole"));
}

#[test]
fn cloudtrail_stream_stops_before_a_later_record() {
    let bytes = br#"{"Records":[{"eventName":"First"},{"eventName":"Second"}]}"#;
    let mut seen = Vec::new();
    let result = JsonParser.parse_each(
        "cloudtrail.json",
        bytes,
        &irmind_app::CancellationToken::new(),
        &mut |record| {
            record.inspect(|value| seen.push(value.event.clone()));
            Err(AppError::Cancelled)
        },
    );
    assert!(matches!(result, Err(AppError::Cancelled)));
    assert_eq!(seen, ["First"]);
}

#[test]
fn newline_json_stream_has_stable_record_pointers() {
    let bytes = b"{\"eventName\":\"First\"}\n{\"eventName\":\"Second\"}\n";
    let mut pointers = Vec::new();
    let count = JsonParser
        .parse_each(
            "events.jsonl",
            bytes,
            &irmind_app::CancellationToken::new(),
            &mut |record| {
                record.inspect(|value| pointers.push(value.index));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(pointers, [0, 1]);
}

#[test]
fn streamed_file_records_keep_parser_and_byte_offset_provenance() {
    let bytes = b"{\"eventName\":\"First\"}\n{\"eventName\":\"Second\"}\n";
    let mut offsets = Vec::new();
    JsonParser
        .parse_reader(
            "events.jsonl",
            &mut bytes.as_slice(),
            sha256(bytes),
            &irmind_app::CancellationToken::new(),
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
    JsonParser
        .parse_reader(
            "array.json",
            &mut array.as_slice(),
            sha256(array),
            &irmind_app::CancellationToken::new(),
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
    let report = StreamingEventParser::parse_reader_report(
        &JsonParser,
        "events.jsonl",
        &mut bytes.as_slice(),
        sha256(bytes),
        &irmind_app::CancellationToken::new(),
        &mut |record| {
            record.inspect(|value| names.push(value.event.clone()));
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
fn rejects_excessive_size_depth_and_record_count() {
    let oversized = vec![b' '; 50 * 1024 * 1024 + 1];
    assert!(JsonParser.parse("large.json", &oversized).is_err());
    let deeply_nested = format!("{}0{}", "[".repeat(130), "]".repeat(130));
    assert!(
        JsonParser
            .parse("nested.json", deeply_nested.as_bytes())
            .is_err()
    );
    let many = format!("[{}]", "{},".repeat(100_000) + "{}");
    assert!(JsonParser.parse("many.json", many.as_bytes()).is_err());
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
        let count = JsonParser
            .parse_reader(
                source,
                &mut json.as_bytes(),
                sha256(json.as_bytes()),
                &irmind_app::CancellationToken::new(),
                &mut |record| {
                    record.inspect(|value| parsed.push((value.at.clone(), value.event.clone())));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(count, 1, "{source}");
        assert_eq!(parsed[0].0, "2026-10-23T12:00:00Z", "{source}");
        assert_eq!(parsed[0].1, event, "{source}");
    }
}

#[test]
fn streaming_reader_rejects_oversized_record_before_emitting_it() {
    let long_value = "x".repeat(4 * 1024 * 1024);
    let json = format!("{{\"message\":\"{long_value}\"}}");
    let mut emitted = 0;
    let result = JsonParser.parse_reader(
        "oversized.json",
        &mut json.as_bytes(),
        sha256(json.as_bytes()),
        &irmind_app::CancellationToken::new(),
        &mut |_| {
            emitted += 1;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(emitted, 0);
}
