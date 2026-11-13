use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{
    CommonField as F, EntityIdentityScope, EntityRole, EventCategory, EventOutcome,
};
const SAMPLE: &[u8] = br#"{"time_dt":"2026-11-01T00:00:00.123456789Z","class_uid":3002,"category_uid":3,"activity_id":1,"activity_name":"Logon","status_id":2,"metadata":{"version":"1.4.0"},"device":{"hostname":"synthetic-host"},"actor":{"user":{"name":"alice","domain":"CORP-A"}},"user":{"name":"bob","domain":"CORP-B"},"src_endpoint":{"ip":"203.0.113.77"},"dst_endpoint":{"ip":"203.0.113.77"},"process":{"pid":42,"parent_process":{"pid":7}},"unmapped":"synthetic only"}"#;
fn records(bytes: &[u8]) -> Vec<SourceRecordV1> {
    let mut rows = Vec::new();
    let cancel = CancellationToken::new();
    let reference = SourceReferenceV1::file("synthetic.jsonl").unwrap();
    let report = irmind_mod_parser_ocsf::OcsfSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |row| {
                row.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.rejected, 0);
    rows
}
#[test]
fn explicit_ocsf_roles_preserve_both_occurrences_and_precise_time() {
    let source = records(SAMPLE).remove(0);
    let output = OcsfMapping::new().unwrap().map(&source).unwrap();
    let common = &output.record().common;
    assert!(
        common
            .event()
            .categories()
            .contains(EventCategory::Authentication)
    );
    assert_eq!(common.event().outcome(), EventOutcome::Failure);
    assert_eq!(
        common.timestamp().unwrap().to_rfc3339(),
        "2026-11-01T00:00:00.123456789Z"
    );
    let at = |field| {
        common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == field)
            .unwrap()
    };
    assert_eq!(at(F::SourceIp).entity(), at(F::DestinationIp).entity());
    assert_eq!(at(F::SourceIp).role(), EntityRole::Source);
    assert_eq!(at(F::DestinationIp).role(), EntityRole::Destination);
    assert_eq!(at(F::UserName).role(), EntityRole::Actor);
    assert_eq!(at(F::UserTargetName).role(), EntityRole::Target);
    assert_ne!(at(F::UserName).entity(), at(F::UserTargetName).entity());
    assert!(
        output
            .record()
            .indexed
            .record
            .text
            .contains("synthetic only")
    );
}
#[test]
fn outcomes_are_closed_and_missing_is_unknown_without_action_inference() {
    let text = std::str::from_utf8(SAMPLE).unwrap();
    let mapper = OcsfMapping::new().unwrap();
    for (suffix, expected) in [
        ("\"status_id\":1,", EventOutcome::Success),
        ("\"status_id\":2,", EventOutcome::Failure),
        ("", EventOutcome::Unknown),
        ("\"status_id\":99,", EventOutcome::Unknown),
        (
            "\"status_id\":1,\"status\":\"Failure\",",
            EventOutcome::Unknown,
        ),
    ] {
        let bytes = text
            .replace("\"status_id\":2,", suffix)
            .replace("Logon", "authentication failure");
        let out = mapper.map(&records(bytes.as_bytes()).remove(0)).unwrap();
        assert_eq!(out.record().common.event().outcome(), expected);
    }
}
#[test]
fn other_versions_and_unmapped_classes_remain_searchable_unclassified() {
    let text = std::str::from_utf8(SAMPLE).unwrap();
    let mapper = OcsfMapping::new().unwrap();
    for bytes in [
        text.replace("1.4.0", "1.5.0"),
        text.replace("\"class_uid\":3002", "\"class_uid\":9999"),
        text.replace("\"category_uid\":3", "\"category_uid\":4"),
    ] {
        let out = mapper.map(&records(bytes.as_bytes()).remove(0)).unwrap();
        assert_eq!(out.record().common.event().categories().bits(), 0);
        assert_eq!(out.record().common.event().outcome(), EventOutcome::Unknown);
        assert!(out.record().common.observations().values().is_empty());
        assert!(
            out.record()
                .indexed
                .record
                .entities
                .contains(&("ip".into(), "203.0.113.77".into()))
        );
    }
}
#[test]
fn explicit_realm_and_record_scope_prevent_user_and_pid_aliasing() {
    let text = std::str::from_utf8(SAMPLE).unwrap().replace("bob", "alice");
    let bytes = format!("{text}\n{text}\n");
    let sources = records(bytes.as_bytes());
    let mapper = OcsfMapping::new().unwrap();
    let a = mapper.map(&sources[0]).unwrap();
    let at = |out: &MappingOutput, field| {
        out.record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == field)
            .unwrap()
            .entity()
            .clone()
    };
    assert_ne!(at(&a, F::UserName), at(&a, F::UserTargetName));
    let process_text = bytes
        .replace("\"class_uid\":3002", "\"class_uid\":1007")
        .replace("\"category_uid\":3", "\"category_uid\":1");
    let processes = records(process_text.as_bytes());
    let a = mapper.map(&processes[0]).unwrap();
    let b = mapper.map(&processes[1]).unwrap();
    assert_ne!(at(&a, F::ProcessPid), at(&b, F::ProcessPid));
    for field in [F::ProcessPid, F::ProcessParentPid] {
        assert!(matches!(
            at(&a, field).scope(),
            EntityIdentityScope::SourceRecord { .. }
        ));
    }
}
#[test]
fn invalid_typed_fields_are_rejected_and_all_six_classes_are_explicit() {
    let text = std::str::from_utf8(SAMPLE).unwrap();
    let mapper = OcsfMapping::new().unwrap();
    for bad in [
        text.replace("203.0.113.77", "not an IP"),
        text.replace("\"pid\":42", "\"pid\":-1")
            .replace("\"class_uid\":3002", "\"class_uid\":1007")
            .replace("\"category_uid\":3", "\"category_uid\":1"),
    ] {
        assert!(mapper.map(&records(bad.as_bytes()).remove(0)).is_err());
    }
    for (class, category, expected) in [
        (1001, 1, EventCategory::File),
        (1007, 1, EventCategory::Process),
        (2004, 2, EventCategory::IntrusionDetection),
        (3002, 3, EventCategory::Authentication),
        (4001, 4, EventCategory::Network),
        (6003, 6, EventCategory::Api),
    ] {
        let bytes = text
            .replace("\"class_uid\":3002", &format!("\"class_uid\":{class}"))
            .replace(
                "\"category_uid\":3",
                &format!("\"category_uid\":{category}"),
            );
        let out = mapper.map(&records(bytes.as_bytes()).remove(0)).unwrap();
        assert!(out.record().common.event().categories().contains(expected));
    }
}
#[test]
fn mapping_passes_shared_purity_and_limits_contract() {
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_ocsf::OcsfSourceDecoder),
        Arc::new(OcsfMapping::new().unwrap()),
        "synthetic.ndjson",
        SAMPLE,
        1,
    )
    .unwrap();
}

#[test]
fn unrelated_root_fields_never_assign_authentication_or_process_roles() {
    let text = std::str::from_utf8(SAMPLE)
        .unwrap()
        .replace("\"class_uid\":3002", "\"class_uid\":1001")
        .replace("\"category_uid\":3", "\"category_uid\":1");
    let output = OcsfMapping::new()
        .unwrap()
        .map(&records(text.as_bytes()).remove(0))
        .unwrap();
    for field in [
        F::UserTargetName,
        F::UserTargetId,
        F::ProcessPid,
        F::ProcessParentPid,
    ] {
        assert!(output.record().common.context().get(field).is_none());
    }
    assert!(output.record().indexed.record.text.contains("bob"));
}
