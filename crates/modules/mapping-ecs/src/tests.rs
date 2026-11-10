use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1, SourceValue},
};
use irmind_domain::{
    CommonField as F, EntityIdentityScope, EntityRole, EventCategory, EventOutcome,
};
fn records(bytes: &[u8]) -> Vec<SourceRecordV1> {
    let mut rows = Vec::new();
    let cancel = CancellationToken::new();
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let report = irmind_mod_parser_ecs::EcsSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |row| {
                row.inspect(|row| rows.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.rejected, 0);
    rows
}
const SAMPLE: &[u8] = br#"{"@timestamp":"2026-11-01T00:00:00.123456789Z","ecs":{"version":"9.5.0"},"event":{"category":["authentication"],"type":["start"],"outcome":"failure","kind":"event","action":"login"},"host":{"name":"synthetic-host"},"user":{"name":"alice","domain":"CORP-A","target":{"name":"bob","domain":"CORP-B"}},"source":{"ip":"203.0.113.77"},"destination":{"ip":"203.0.113.77"},"process":{"pid":42,"parent":{"pid":7}},"message":"synthetic only"}"#;
#[test]
fn native_categories_outcomes_roles_and_precise_time_are_explicit() {
    let source = records(SAMPLE).remove(0);
    let output = EcsMapping::new().unwrap().map(&source).unwrap();
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
    let observed = common.observations().values();
    let at = |field| observed.iter().find(|o| o.field() == field).unwrap();
    assert_eq!(at(F::SourceIp).entity(), at(F::DestinationIp).entity());
    assert_eq!(at(F::SourceIp).role(), EntityRole::Source);
    assert_eq!(at(F::DestinationIp).role(), EntityRole::Destination);
    assert_eq!(at(F::UserName).role(), EntityRole::Actor);
    assert_eq!(at(F::UserTargetName).role(), EntityRole::Target);
    assert_ne!(at(F::UserName).entity(), at(F::UserTargetName).entity());
    for field in [F::ProcessPid, F::ProcessParentPid] {
        assert!(matches!(
            at(field).entity().scope(),
            EntityIdentityScope::SourceRecord { .. }
        ));
    }
}
#[test]
fn no_action_text_inference_and_unknown_labels_remain_diagnostic() {
    let mapper = EcsMapping::new().unwrap();
    let input = br#"{"@timestamp":"2026-11-01T00:00:00Z","ecs":{"version":"9.5.0"},"event":{"action":"authentication failure"}}"#;
    let source = records(input).remove(0);
    let output = mapper.map(&source).unwrap();
    assert_eq!(output.record().common.event().categories().bits(), 0);
    assert_eq!(
        output.record().common.event().outcome(),
        EventOutcome::Unknown
    );
    let text = std::str::from_utf8(SAMPLE)
        .unwrap()
        .replace("authentication", "unrecognized-category")
        .replace("failure", "unrecognized-outcome");
    let output = mapper.map(&records(text.as_bytes()).remove(0)).unwrap();
    assert_eq!(output.record().common.event().categories().bits(), 0);
    assert_eq!(
        output.record().common.event().outcome(),
        EventOutcome::Unknown
    );
    assert!(
        output
            .diagnostics()
            .contains(&MappingDiagnostic::UnsupportedValue)
    );
}
#[test]
fn same_username_in_distinct_reported_realms_is_not_one_account() {
    let text = std::str::from_utf8(SAMPLE).unwrap().replace("bob", "alice");
    let output = EcsMapping::new()
        .unwrap()
        .map(&records(text.as_bytes()).remove(0))
        .unwrap();
    let observations = output.record().common.observations().values();
    let actor = observations
        .iter()
        .find(|o| o.field() == F::UserName)
        .unwrap();
    let target = observations
        .iter()
        .find(|o| o.field() == F::UserTargetName)
        .unwrap();
    assert_eq!(actor.entity().value(), target.entity().value());
    assert_ne!(actor.entity(), target.entity());
}
#[test]
fn missing_status_and_reused_pid_never_invent_success_or_lifetimes() {
    let text = std::str::from_utf8(SAMPLE)
        .unwrap()
        .replace("\"outcome\":\"failure\",", "");
    let bytes = format!("{text}\n{text}\n");
    let sources = records(bytes.as_bytes());
    let mapper = EcsMapping::new().unwrap();
    let a = mapper.map(&sources[0]).unwrap();
    let b = mapper.map(&sources[1]).unwrap();
    assert_eq!(a.record().common.event().outcome(), EventOutcome::Unknown);
    let process = |output: &MappingOutput| {
        output
            .record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == F::ProcessPid)
            .unwrap()
            .entity()
            .clone()
    };
    assert_ne!(process(&a), process(&b));
    assert!(matches!(
        process(&a).scope(),
        EntityIdentityScope::SourceRecord { .. }
    ));
}
#[test]
fn invalid_typed_values_and_conflicting_dotted_aliases_fail_mapping() {
    let text = std::str::from_utf8(SAMPLE).unwrap();
    for text in [
        text.replace("203.0.113.77", "not-an-ip"),
        text.replace("\"pid\":42", "\"pid\":-1"),
        text.replace(
            "\"message\":",
            "\"host.name\":\"different-host\",\"message\":",
        ),
    ] {
        assert!(
            EcsMapping::new()
                .unwrap()
                .map(&records(text.as_bytes()).remove(0))
                .is_err()
        );
    }
}
#[test]
fn extraction_projection_and_shared_contract_preserve_search_and_originals() {
    let sample = include_bytes!("../../../testkit/fixtures/parser-ecs/source/events.ndjson");
    let source = records(sample).remove(0);
    assert!(matches!(
        source.fields().field("custom"),
        Some(SourceValue::Object(_))
    ));
    let mapper = EcsMapping::new().unwrap();
    let output = mapper.map(&source).unwrap();
    assert!(
        output
            .record()
            .indexed
            .record
            .entities
            .contains(&("user".into(), "synthetic-user".into()))
    );
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_ecs::EcsSourceDecoder),
        Arc::new(mapper),
        "synthetic.ndjson",
        sample,
        2,
    )
    .unwrap();
}

#[test]
fn identical_names_in_two_roles_share_identity_only_in_the_same_namespace() {
    let text = std::str::from_utf8(SAMPLE)
        .unwrap()
        .replace("bob", "alice")
        .replace("CORP-B", "CORP-A");
    let output = EcsMapping::new()
        .unwrap()
        .map(&records(text.as_bytes()).remove(0))
        .unwrap();
    let values = output.record().common.observations().values();
    let actor = values.iter().find(|o| o.field() == F::UserName).unwrap();
    let target = values
        .iter()
        .find(|o| o.field() == F::UserTargetName)
        .unwrap();
    assert_eq!(actor.entity(), target.entity());
    assert_ne!(actor.role(), target.role());
}
