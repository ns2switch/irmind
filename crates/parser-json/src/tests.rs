use super::*;

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
