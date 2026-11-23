use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use std::sync::Arc;
fn mapped(bytes: &[u8]) -> Vec<MappingOutput> {
    let source = SourceReferenceV1::file("synthetic.data").unwrap();
    let cancel = CancellationToken::new();
    let mapper = DefenderMapping::new().unwrap();
    let mut output = Vec::new();
    irmind_mod_parser_defender::DefenderSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |record| {
                record.inspect(|r| output.push(mapper.map(r).unwrap()));
                Ok(())
            },
        )
        .unwrap();
    output
}
#[test]
fn finite_tables_and_mapping_contract_cover_json_csv_and_streaming() {
    for (name, bytes) in [
        (
            "events.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/events.ndjson")
                .as_slice(),
        ),
        (
            "api.json",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/api.json").as_slice(),
        ),
        (
            "stream.json",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/stream.json")
                .as_slice(),
        ),
        (
            "hunting.csv",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/hunting.csv")
                .as_slice(),
        ),
    ] {
        irmind_testkit::run_source_mapping_contract(
            Arc::new(irmind_mod_parser_defender::DefenderSourceDecoder),
            Arc::new(DefenderMapping::new().unwrap()),
            name,
            bytes,
            9,
        )
        .unwrap();
        let output = mapped(bytes);
        assert!(output.iter().all(|o| o.diagnostics().is_empty()));
        assert_eq!(
            output[4].record().common.event().outcome(),
            irmind_domain::EventOutcome::Failure
        );
        assert_eq!(
            output[7].record().common.event().kind(),
            irmind_domain::EventKind::Alert
        );
        assert_eq!(
            output[8].record().common.event().kind(),
            irmind_domain::EventKind::Alert
        );
        assert!(
            output
                .iter()
                .flat_map(|r| r.record().common.observations().values())
                .all(|o| !matches!(
                    o.entity().scope(),
                    irmind_domain::EntityIdentityScope::ProcessLifetime { .. }
                ))
        );
    }
}
#[test]
fn actor_target_and_pid_roles_are_record_scoped_without_lifetime_inference() {
    let output = mapped(include_bytes!(
        "../../../testkit/fixtures/parser-defender/source/events.ndjson"
    ));
    let observations = output[0].record().common.observations().values();
    for (value, role) in [
        ("actor", irmind_domain::EntityRole::Actor),
        ("target", irmind_domain::EntityRole::Target),
        ("200", irmind_domain::EntityRole::Subject),
        ("100", irmind_domain::EntityRole::Parent),
    ] {
        assert!(
            observations
                .iter()
                .any(|o| o.entity().value() == value && o.role() == role)
        );
    }
    assert_eq!(output[0].partition().host(), "synthetic-device-a");
}

#[test]
fn network_roles_follow_explicit_direction_even_for_the_same_address() {
    let row = include_str!("../../../testkit/fixtures/parser-defender/source/events.ndjson")
        .lines()
        .nth(1)
        .unwrap();
    let output = mapped(row.as_bytes());
    let observations = output[0].record().common.observations().values();
    assert!(observations.iter().any(
        |o| o.role() == irmind_domain::EntityRole::Source && o.entity().value() == "192.0.2.10"
    ));
    let incoming = row.replace("ConnectionSuccess", "InboundConnectionAccepted");
    let output = mapped(incoming.as_bytes());
    let observations = output[0].record().common.observations().values();
    assert!(
        observations
            .iter()
            .any(|o| o.role() == irmind_domain::EntityRole::Source
                && o.entity().value() == "203.0.113.77")
    );
    assert!(
        observations
            .iter()
            .any(|o| o.role() == irmind_domain::EntityRole::Destination
                && o.entity().value() == "192.0.2.10")
    );
    let same = row.replace("192.0.2.10", "203.0.113.77");
    let output = mapped(same.as_bytes());
    let observations = output[0].record().common.observations().values();
    assert_eq!(
        observations
            .iter()
            .filter(|o| o.entity().value() == "203.0.113.77")
            .count(),
        2
    );
}
#[test]
fn repeated_pids_have_distinct_source_record_scope_and_equal_users_keep_two_roles() {
    let row = include_str!("../../../testkit/fixtures/parser-defender/source/events.ndjson")
        .lines()
        .next()
        .unwrap();
    let repeated = format!("{row}\n{row}\n");
    let output = mapped(repeated.as_bytes());
    let process = |o: &MappingOutput| {
        o.record()
            .common
            .observations()
            .values()
            .iter()
            .find(|v| {
                v.entity().kind() == irmind_domain::ObservedEntityKind::Process
                    && v.role() == irmind_domain::EntityRole::Subject
            })
            .unwrap()
            .entity()
            .scope()
            .clone()
    };
    assert_ne!(process(&output[0]), process(&output[1]));
    let host = |output: &MappingOutput| {
        output
            .record()
            .common
            .observations()
            .values()
            .iter()
            .find(|v| v.entity().kind() == irmind_domain::ObservedEntityKind::Host)
            .unwrap()
            .entity()
            .clone()
    };
    assert_eq!(host(&output[0]), host(&output[1]));
    let same = row.replace("\"AccountName\": \"target\"", "\"AccountName\": \"actor\"");
    let output = mapped(same.as_bytes());
    assert_eq!(
        output[0]
            .record()
            .common
            .observations()
            .values()
            .iter()
            .filter(|o| o.entity().value() == "actor")
            .count(),
        2
    );
}
#[test]
fn unknown_status_retains_original_fields_without_a_guessed_success() {
    let row = include_str!("../../../testkit/fixtures/parser-defender/source/events.ndjson")
        .lines()
        .next()
        .unwrap()
        .replace("ProcessCreated", "SyntheticUnknownAction");
    let output = mapped(row.as_bytes());
    assert_eq!(
        output[0].record().common.event().outcome(),
        irmind_domain::EventOutcome::Unknown
    );
    assert_eq!(output[0].record().common.event().categories().bits(), 0);
    assert!(
        output[0]
            .record()
            .indexed
            .record
            .text
            .contains("SyntheticUnknownAction")
    );
}
