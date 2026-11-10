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
        index: 3,
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
