use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{EntityRole, EventCategory, EventOutcome, EventType};
use irmind_mod_parser_google_workspace::GoogleWorkspaceSourceDecoder;
use std::sync::Arc;

const FIXTURE: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-google-workspace/source/events.ndjson");

#[test]
fn mapped_events_pass_the_shared_contract() {
    irmind_testkit::run_source_mapping_contract(
        Arc::new(GoogleWorkspaceSourceDecoder),
        Arc::new(GoogleWorkspaceMapping::new().unwrap()),
        "events.ndjson",
        FIXTURE,
        9,
    )
    .unwrap();
}

#[test]
fn roles_outcomes_unknown_events_and_gmail_subtypes_remain_distinct() {
    let mapper = GoogleWorkspaceMapping::new().unwrap();
    let source = SourceReferenceV1::file("events.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let mut bytes = FIXTURE;
    let report = GoogleWorkspaceSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(FIXTURE),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes,
            },
            &mut |row| {
                row.inspect(|row| records.push(mapper.map(row).unwrap().into_record()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (9, 0));
    assert_eq!(records[0].common.event().outcome(), EventOutcome::Failure);
    assert_eq!(records[1].common.event().outcome(), EventOutcome::Success);
    assert!(
        records[0]
            .common
            .event()
            .categories()
            .contains(EventCategory::Authentication)
    );
    for (index, role, value) in [
        (0, EntityRole::Source, "203.0.113.77"),
        (2, EntityRole::Target, "synthetic-client"),
        (3, EntityRole::Target, "synthetic-document"),
        (5, EntityRole::Target, "other-test@example.test"),
        (5, EntityRole::Actor, "admin-test@example.test"),
    ] {
        assert!(
            records[index]
                .common
                .observations()
                .values()
                .iter()
                .any(|observation| observation.role() == role
                    && observation.entity().value() == value),
            "missing {role:?} observation on record {index}"
        );
    }
    assert!(
        records[4]
            .common
            .event()
            .categories()
            .iter()
            .next()
            .is_none()
    );
    assert!(
        records[4]
            .indexed
            .record
            .text
            .contains("raw-value-preserved")
    );
    assert_eq!(records[6].common.event().outcome(), EventOutcome::Failure);
    assert_eq!(records[8].common.event().action(), Some("delivery"));
    assert_eq!(records[8].common.event().code(), Some("11"));
    assert!(
        records[8]
            .common
            .event()
            .types()
            .contains(EventType::Change)
    );
}
