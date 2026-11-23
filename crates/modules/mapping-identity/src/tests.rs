use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use std::sync::Arc;
fn records(decoder: &dyn SourceDecoder, mut bytes: &[u8]) -> Vec<SourceRecordV1> {
    let source = SourceReferenceV1::file("events.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    decoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes,
            },
            &mut |r| {
                r.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    rows
}
#[test]
fn m365_contract_classifies_bec_and_preserves_unknown_data() {
    let bytes = include_bytes!("../../../testkit/fixtures/parser-m365/source/events.ndjson");
    let mapper = IdentityMapping::m365().unwrap();
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_m365::M365SourceDecoder),
        Arc::new(IdentityMapping::m365().unwrap()),
        "events.ndjson",
        bytes,
        8,
    )
    .unwrap();
    let rows = records(&irmind_mod_parser_m365::M365SourceDecoder, bytes);
    let first = mapper.map(&rows[0]).unwrap().into_record();
    assert!(
        first
            .common
            .event()
            .categories()
            .contains(EventCategory::Authentication)
    );
    assert_eq!(
        first.common.event().outcome(),
        irmind_domain::EventOutcome::Failure
    );
    let unknown = mapper.map(&rows[7]).unwrap().into_record();
    assert!(
        unknown
            .common
            .event()
            .categories()
            .contains(EventCategory::Api)
    );
    assert_eq!(
        unknown.common.event().outcome(),
        irmind_domain::EventOutcome::Unknown
    );
    assert!(
        unknown
            .indexed
            .record
            .text
            .contains("ForwardingSmtpAddress")
    );
}
#[test]
fn okta_actor_target_and_missing_status_are_distinct() {
    let bytes = include_bytes!("../../../testkit/fixtures/parser-okta/source/events.ndjson");
    let mapper = IdentityMapping::okta().unwrap();
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_okta::OktaSourceDecoder),
        Arc::new(IdentityMapping::okta().unwrap()),
        "events.ndjson",
        bytes,
        7,
    )
    .unwrap();
    let rows = records(&irmind_mod_parser_okta::OktaSourceDecoder, bytes);
    let projection = mapper.map(&rows[0]).unwrap().into_record();
    assert_eq!(
        projection.common.event().outcome(),
        irmind_domain::EventOutcome::Failure
    );
    assert!(
        projection
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.role() == R::Actor && o.entity().value() == "alice@example.invalid")
    );
    assert!(
        projection
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.role() == R::Target && o.entity().value() == "bob@example.invalid")
    );
    assert_eq!(
        mapper
            .map(&rows[5])
            .unwrap()
            .into_record()
            .common
            .event()
            .outcome(),
        irmind_domain::EventOutcome::Unknown
    );
}

#[test]
fn multiple_okta_targets_remain_searchable_without_invalid_scalar_observations() {
    let bytes=br#"{"uuid":"synthetic-1","published":"2026-01-01T00:00:00Z","eventType":"user.account.privilege.grant","actor":{"id":"actor","alternateId":"alice@example.invalid"},"target":[{"type":"User","id":"one","alternateId":"bob@example.invalid"},{"type":"User","id":"two","alternateId":"carol@example.invalid"}],"outcome":{"result":"SUCCESS"}}"#;
    let rows = records(&irmind_mod_parser_okta::OktaSourceDecoder, bytes);
    let projection = IdentityMapping::okta()
        .unwrap()
        .map(&rows[0])
        .unwrap()
        .into_record();
    assert!(
        projection
            .indexed
            .record
            .text
            .contains("carol@example.invalid")
    );
    assert!(
        projection
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.entity().value() == "bob@example.invalid")
    );
    assert!(
        projection
            .common
            .observations()
            .values()
            .iter()
            .all(|o| !matches!(
                o.entity().scope(),
                EntityIdentityScope::ProcessLifetime { .. }
            ))
    );
}

#[test]
fn m365_placeholder_identities_are_not_observations() {
    let bytes=br#"{"Id":"synthetic-placeholder","Operation":"FutureOperation","CreationTime":"2026-01-01T00:00:00Z","Workload":"Exchange","OrganizationId":"-","UserId":"-","ObjectId":"-","MailboxOwnerUPN":"-"}"#;
    let rows = records(&irmind_mod_parser_m365::M365SourceDecoder, bytes);
    let output = IdentityMapping::m365().unwrap().map(&rows[0]).unwrap();
    assert!(output.partition().account().is_empty());
    let projection = output.into_record();
    assert!(
        projection
            .common
            .observations()
            .values()
            .iter()
            .all(|o| o.entity().value() != "-")
    );
}
