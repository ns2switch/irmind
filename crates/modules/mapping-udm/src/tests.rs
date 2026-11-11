use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder as _,
    source_mapping::{SourceInput, SourceMetadata},
};
use irmind_domain::{
    CommonField as F, EntityIdentityScope, EntityRole, EventCategory, EventOutcome,
    SourceReferenceV1,
};
const SAMPLE: &[u8] = br#"{"events":[{"udm":{"metadata":{"eventTimestamp":"2026-10-23T00:00:00.123456789Z","eventType":"NETWORK_CONNECTION","productEventType":"OriginalNetworkAction"},"principal":{"user":{"userid":"alice"},"ip":["203.0.113.77"],"process":{"pid":"42"}},"target":{"user":{"userid":"bob"},"ip":["203.0.113.77"]}}},{"udm":{"metadata":{"eventTimestamp":"2026-10-23T00:00:01.123456789Z","eventType":"PROCESS_LAUNCH"},"principal":{"process":{"pid":"42"}}}}]}"#;
fn records(bytes: &[u8]) -> Vec<SourceRecordV1> {
    let reference = SourceReferenceV1::file("synthetic-udm.json").unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let report = irmind_mod_siem_chronicle::ChronicleSourceDecoder
        .decode_reader(
            SourceInput {
                reader: &mut &bytes[..],
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
            },
            &mut |record| {
                record.inspect(|record| records.push(record.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.rejected, 0);
    records
}
#[test]
fn explicit_roles_share_ips_but_do_not_merge_users_or_reused_process_ids() {
    let source = records(SAMPLE);
    let mapper = UdmMapping::new().unwrap();
    let first = mapper.map(&source[0]).unwrap();
    let second = mapper.map(&source[1]).unwrap();
    let observed = first.record().common.observations().values();
    let at = |field| observed.iter().find(|o| o.field() == field).unwrap();
    assert_eq!(at(F::SourceIp).role(), EntityRole::Source);
    assert_eq!(at(F::DestinationIp).role(), EntityRole::Destination);
    assert_eq!(at(F::SourceIp).entity(), at(F::DestinationIp).entity());
    assert_ne!(at(F::UserId).entity(), at(F::UserTargetId).entity());
    assert_eq!(at(F::UserId).role(), EntityRole::Actor);
    assert_eq!(at(F::UserTargetId).role(), EntityRole::Target);
    assert!(matches!(
        at(F::ProcessPid).entity().scope(),
        EntityIdentityScope::SourceRecord { record: 0, .. }
    ));
    assert_ne!(
        at(F::ProcessPid).entity(),
        second
            .record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == F::ProcessPid)
            .unwrap()
            .entity()
    );
    assert_eq!(
        first.record().common.timestamp().unwrap().to_rfc3339(),
        "2026-10-23T00:00:00.123456789Z"
    );
    assert!(
        first
            .record()
            .common
            .event()
            .categories()
            .contains(EventCategory::Network)
    );
    assert!(source[0].origin().offset().is_none());
}
#[test]
fn security_block_does_not_invent_authentication_failure_or_unknown_event_classification() {
    for (kind, expected) in [("USER_LOGIN", true), ("UNKNOWN_VENDOR_EVENT", false)] {
        let sample = format!(
            r#"{{"events":[{{"udm":{{"metadata":{{"eventTimestamp":"2026-10-23T00:00:00Z","eventType":"{kind}"}},"securityResult":[{{"action":"BLOCK","summary":"authentication failure"}}]}}}}]}}"#
        );
        let output = UdmMapping::new()
            .unwrap()
            .map(&records(sample.as_bytes())[0])
            .unwrap();
        assert_eq!(
            output.record().common.event().outcome(),
            EventOutcome::Unknown
        );
        assert_eq!(
            output
                .record()
                .common
                .event()
                .categories()
                .contains(EventCategory::Authentication),
            expected
        );
        assert!(
            output
                .record()
                .indexed
                .record
                .text
                .contains("authentication failure")
        );
    }
}
#[test]
fn unsupported_repeated_values_remain_original_with_a_coverage_diagnostic() {
    let sample = std::str::from_utf8(SAMPLE).unwrap().replacen(
        "[\"203.0.113.77\"]",
        "[\"203.0.113.77\",\"203.0.113.78\"]",
        1,
    );
    let output = UdmMapping::new()
        .unwrap()
        .map(&records(sample.as_bytes())[0])
        .unwrap();
    assert!(
        output
            .diagnostics()
            .contains(&irmind_app::source_mapping::MappingDiagnostic::UnsupportedValue)
    );
    assert!(output.record().common.context().get(F::SourceIp).is_none());
    assert!(output.record().indexed.record.text.contains("203.0.113.78"));
    for value in ["203.0.113.77", "203.0.113.78"] {
        assert!(
            output
                .record()
                .indexed
                .record
                .entities
                .contains(&("ip".into(), value.into()))
        );
    }
}
#[test]
fn malformed_typed_values_fail_mapping_instead_of_removing_a_filter() {
    let sample = std::str::from_utf8(SAMPLE)
        .unwrap()
        .replace("203.0.113.77", "not-an-ip");
    assert!(
        UdmMapping::new()
            .unwrap()
            .map(&records(sample.as_bytes())[0])
            .is_err()
    );
}
#[test]
fn decoder_mapping_shared_contract_is_deterministic_and_cancellable() {
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_siem_chronicle::ChronicleSourceDecoder),
        Arc::new(UdmMapping::new().unwrap()),
        "synthetic-udm.json",
        SAMPLE,
        2,
    )
    .unwrap();
}
