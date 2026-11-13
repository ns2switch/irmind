#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
use irmind_app::source_mapping::{SourceInput, SourceMetadata};
use irmind_app::{AppError, CancellationToken, GraphRecord, SourceDecoder, SourceMapper};
use irmind_domain::{SourceReferenceV1, Tainted};
use irmind_mod_mapping_json_compat::JsonCompatibilityMapping;
struct MappedJson;
impl MappedJson {
    fn parse(source: &str, bytes: &[u8]) -> Result<Vec<Tainted<GraphRecord>>, AppError> {
        let mut rows = Vec::new();
        Self::parse_each(source, bytes, &CancellationToken::new(), &mut |row| {
            rows.push(row);
            Ok(())
        })?;
        Ok(rows)
    }
    fn parse_each(
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        let source = SourceReferenceV1::file(source).unwrap();
        let mapping = JsonCompatibilityMapping::new().unwrap();
        irmind_mod_parser_json::JsonSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: irmind_app::sha256(bytes),
                        time_context: None,
                        cluster_context: None,
                        cancel,
                    },
                    reader: &mut std::io::Cursor::new(bytes),
                },
                &mut |record| {
                    let mut output = None;
                    record.inspect(|source| output = Some(mapping.map(source)));
                    let output = output
                        .unwrap()
                        .map_err(irmind_app::source_mapping::MappingError::into_app)?;
                    emit(Tainted::from_external(
                        output.record().indexed.record.clone(),
                        record.provenance().clone(),
                    ))
                },
            )
            .map(|report| report.accepted)
    }
}

#[test]
fn parses_attributed_hunteval_aws_episode_without_private_answers() {
    let source = include_str!("../../parser-json/tests/fixtures/hunteval-aws-iam-001.json");
    let records =
        MappedJson::parse("hunteval/aws-iam-001/source/events.json", source.as_bytes()).unwrap();
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
        let records = MappedJson::parse("normalized.json", source.to_string().as_bytes()).unwrap();
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
    assert!(MappedJson::parse("normalized.json", record.to_string().as_bytes()).is_err());
}

#[test]
fn indexes_cloudtrail_record() {
    let bytes = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","sourceIPAddress":"203.0.113.8","userIdentity":{"arn":"arn:aws:iam::123456789012:role/Admin"}}]}"#;
    let records = MappedJson::parse("cloudtrail.json", bytes).unwrap();
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
    let records = MappedJson::parse("cloudtrail.json", bytes).unwrap();
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
    let records = MappedJson::parse("cloudtrail.json", bytes).unwrap();
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
    let records = MappedJson::parse("cloud-audit-events/aws.json", cloud).unwrap();
    assert_eq!(records.len(), 2);
    records[1].inspect(|record| assert_eq!(record.event, "GetObject"));
    let splunk = br#"{"result":{"_raw":"{\"eventTime\":\"2026-10-23T12:00:00Z\",\"eventName\":\"AssumeRole\"}"}}"#;
    let records = MappedJson::parse("siem-search/splunk.json", splunk).unwrap();
    assert_eq!(records.len(), 1);
    records[0].inspect(|record| assert_eq!(record.event, "AssumeRole"));
}

#[test]
fn cloudtrail_stream_stops_before_a_later_record() {
    let bytes = br#"{"Records":[{"eventName":"First"},{"eventName":"Second"}]}"#;
    let mut seen = Vec::new();
    let result = MappedJson::parse_each(
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
    let count = MappedJson::parse_each(
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
fn normalized_json_and_capped_entity_selection_ignore_object_insertion_order() {
    let fields = (0..40)
        .map(|index| format!("\"userName{index:02}\":\"synthetic-{index:02}\""))
        .collect::<Vec<_>>();
    let forward = format!("{{{}}}", fields.join(","));
    let reverse = format!(
        "{{{}}}",
        fields.iter().rev().cloned().collect::<Vec<_>>().join(",")
    );
    let parse = |input: &str| {
        let mut rows = Vec::new();
        MappedJson::parse_each(
            "synthetic.json",
            input.as_bytes(),
            &irmind_app::CancellationToken::new(),
            &mut |record| {
                record.inspect(|row| rows.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
        rows
    };
    let rows = parse(&forward);
    assert_eq!(rows, parse(&reverse));
    assert_eq!(rows[0].entities.len(), 32);
    assert!(
        rows[0]
            .entities
            .iter()
            .all(|(_, value)| value.as_str() <= "synthetic-31")
    );
}
