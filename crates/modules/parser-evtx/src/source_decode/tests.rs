use super::*;
use irmind_app::CancellationToken;
use irmind_domain::{SourceReferenceV1, SourceValue};
use serde_json::json;
fn metadata<'a>(
    source: &'a SourceReferenceV1,
    cancel: &'a CancellationToken,
) -> SourceMetadata<'a> {
    SourceMetadata {
        source,
        evidence_hash: [7; 32],
        time_context: None,
        cancel,
    }
}
fn frame(event: serde_json::Value) -> codec::DecodedRecord {
    codec::DecodedRecord {
        accepted_index: 0,
        record_id: 91,
        offset: 4608,
        timestamp: "2026-11-01T00:00:00.1234567Z".into(),
        event,
    }
}
#[test]
fn original_fields_keep_types_exact_time_real_offset_and_record_id() {
    let source = SourceReferenceV1::file("Security.evtx").unwrap();
    let cancel = CancellationToken::new();
    let record = decode(frame(json!({"Event":{"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},"Channel":"Security","EventID":4625},"EventData":{"Status":"0xc000006d","TargetUserName":"-"}}})), metadata(&source, &cancel)).unwrap();
    assert_eq!(
        record.provenance().parser_location().unwrap().byte_offset(),
        4608
    );
    record.inspect(|record| {
        assert_eq!(record.origin().record(), 0);
        assert_eq!(record.annotations().members()[0].ordinal, 91);
        assert_eq!(record.timestamp().unwrap().instant().submicro_nanos(), 700);
        assert!(matches!(
            record
                .fields()
                .field("Event")
                .unwrap()
                .field("System")
                .unwrap()
                .field("EventID"),
            Some(SourceValue::Number(_))
        ));
        assert_eq!(
            record
                .format()
                .discriminators()
                .get(&SourceDiscriminator::Provider)
                .unwrap(),
            "Microsoft-Windows-Security-Auditing"
        );
        assert!(record.fields().field("outcome").is_none());
    });
}
#[test]
fn missing_provider_is_preserved_not_inferred_from_channel() {
    let source = SourceReferenceV1::file("Security.evtx").unwrap();
    decode(
        frame(json!({"Event":{"System":{"Channel":"Security","EventID":"4625"}}})),
        metadata(&source, &CancellationToken::new()),
    )
    .unwrap()
    .inspect(|record| {
        assert!(
            !record
                .format()
                .discriminators()
                .contains_key(&SourceDiscriminator::Provider)
        );
    });
}
#[test]
fn source_limits_and_cancellation_are_enforced() {
    let source = SourceReferenceV1::file("Security.evtx").unwrap();
    let fields = serde_json::Value::Array(vec![
        serde_json::Value::Null;
        irmind_domain::SOURCE_MAX_NODES + 1
    ]);
    assert!(decode(frame(fields), metadata(&source, &CancellationToken::new())).is_err());
    let parser = EvtxParser {
        program: None,
        issue: Some("unavailable".into()),
    };
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        parser.decode_reader(
            SourceInput {
                metadata: metadata(&source, &cancel),
                reader: &mut &b""[..]
            },
            &mut |_| Ok(())
        ),
        Err(AppError::Cancelled)
    ));
}

#[test]
fn event_ids_are_decoded_as_original_fields_without_interpretation() {
    use irmind_app::source_mapping::{SourceMetadata, SourceReferenceV1};
    let source = SourceReferenceV1::file("source.evtx").unwrap();
    let cancel = CancellationToken::new();
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
            let row = decode(codec::DecodedRecord {
                accepted_index: 0, record_id: 1, offset: 4608,
                timestamp: "2026-11-01T00:00:00.0000007Z".into(),
                event: json!({"Event":{"System":{"EventID":id,"Channel":channel,"Computer":"synthetic-endpoint"},"EventData":{"TargetUserName":"synthetic-user","IpAddress":"203.0.113.77"}}}),
            }, SourceMetadata { source: &source, evidence_hash: [1;32], time_context: None, cancel: &cancel }).unwrap();
            assert_eq!(
                row.provenance().parser_location().unwrap().byte_offset(),
                4608
            );
            row.inspect(|r| {
                assert_eq!(r.timestamp().unwrap().instant().submicro_nanos(), 700);
                assert_eq!(
                    r.fields()
                        .field("Event")
                        .unwrap()
                        .field("System")
                        .unwrap()
                        .field("Channel")
                        .unwrap()
                        .as_text(),
                    Some(channel)
                );
                assert!(r.fields().field("outcome").is_none());
            });
        }
    }
}
