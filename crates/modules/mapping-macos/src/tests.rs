use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
use irmind_domain::{EntityRole, EventCategory, EventOutcome};
use irmind_mod_parser_macos::MacosSourceDecoder;
use std::sync::Arc;

const ENDPOINT: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-macos/source/endpoint.ndjson");
const UNIFIED: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-macos/source/unified.ndjson");

#[test]
fn each_bundled_table_validates_and_has_distinct_selectors() {
    let mapping = MacosMapping::new().unwrap();
    for (index, table) in mapping.tables.iter().enumerate() {
        for other in &mapping.tables[index + 1..] {
            for left in table.manifest().selectors() {
                for right in other.manifest().selectors() {
                    assert!(left.overlap_witness(right).is_none());
                }
            }
        }
    }
}

#[test]
fn unified_log_keeps_messages_as_source_content() {
    let mapper = MacosMapping::new().unwrap().tables.remove(0);
    irmind_testkit::run_source_mapping_contract(
        Arc::new(MacosSourceDecoder),
        Arc::new(mapper),
        "unified.ndjson",
        UNIFIED,
        2,
    )
    .unwrap();
}

#[test]
fn ssh_result_and_entities_follow_native_fields() {
    let mapping = MacosMapping::new().unwrap();
    for (field, expected) in [
        ("\"success\":true,", EventOutcome::Success),
        ("\"success\":false,", EventOutcome::Failure),
        ("", EventOutcome::Unknown),
    ] {
        let bytes = std::str::from_utf8(ENDPOINT)
            .unwrap()
            .replace("\"success\":false,", field);
        let rows = decode(bytes.as_bytes());
        let row = &rows[1];
        let mapper = mapping
            .tables
            .iter()
            .find(|table| table.manifest().selectors().iter().any(|s| s.matches(row)))
            .unwrap();
        let record = mapper.map(row).unwrap().into_record();
        assert_eq!(record.common.event().outcome(), expected);
        assert!(
            record
                .common
                .event()
                .categories()
                .iter()
                .any(|c| c == EventCategory::Authentication)
        );
        let roles = record.common.observations().values();
        assert!(
            roles
                .iter()
                .any(|o| o.role() == EntityRole::Target && o.entity().value() == "synthetic")
        );
        assert!(
            roles
                .iter()
                .any(|o| o.role() == EntityRole::Source && o.entity().value() == "203.0.113.77")
        );
    }
}

#[test]
fn newer_eslogger_schema_is_not_selected_by_the_v1_tables() {
    let newer = std::str::from_utf8(ENDPOINT)
        .unwrap()
        .replace("\"schema_version\":1", "\"schema_version\":2");
    let mapping = MacosMapping::new().unwrap();
    for row in decode(newer.as_bytes()) {
        assert!(
            mapping.tables.iter().all(|m| m
                .manifest()
                .selectors()
                .iter()
                .all(|s| !s.matches(&row)))
        );
    }
}

fn decode(mut bytes: &[u8]) -> Vec<SourceRecordV1> {
    let source = SourceReferenceV1::file("endpoint.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let report = MacosSourceDecoder
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
            &mut |record| {
                record.inspect(|row| records.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 0));
    records
}

#[test]
fn a_reused_pid_does_not_link_endpoint_records() {
    use irmind_domain::{EntityIdentityScope, ObservedEntityKind};
    let shared_pid = std::str::from_utf8(ENDPOINT)
        .unwrap()
        .replace("\"pid\":303", "\"pid\":302");
    let mapping = MacosMapping::new().unwrap();
    for row in decode(shared_pid.as_bytes()) {
        let record = mapping.map(&row).unwrap().into_record();
        let process = record
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.entity().kind() == ObservedEntityKind::Process)
            .unwrap();
        assert_eq!(process.entity().value(), "302");
        assert!(matches!(
            process.entity().scope(),
            EntityIdentityScope::SourceRecord { record, .. } if *record == row.origin().record()
        ));
    }
}
