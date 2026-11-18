use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
#[test]
fn findings_are_unconfirmed_and_unknown_types_survive() {
    let bytes = include_bytes!("../../../testkit/fixtures/parser-guardduty/source/events.ndjson");
    let mapper = GuardDutyMapping::new().unwrap();
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_guardduty::GuardDutySourceDecoder),
        Arc::new(GuardDutyMapping::new().unwrap()),
        "events.ndjson",
        bytes,
        2,
    )
    .unwrap();
    let source = SourceReferenceV1::file("events.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    irmind_mod_parser_guardduty::GuardDutySourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes.as_slice(),
            },
            &mut |record| {
                record.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    for row in &rows {
        let projection = mapper.map(row).unwrap().into_record();
        assert_eq!(
            projection.common.event().kind(),
            irmind_domain::EventKind::Alert
        );
        assert_eq!(
            projection.common.event().outcome(),
            irmind_domain::EventOutcome::Unknown
        );
        assert!(
            projection
                .indexed
                .record
                .text
                .contains("synthetic-guardduty")
        );
    }
    let projection = mapper.map(&rows[0]).unwrap().into_record();
    assert!(
        projection
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.role() == EntityRole::Source && o.entity().value() == "203.0.113.77")
    );
    assert_eq!(
        projection
            .common
            .context()
            .get(F::IrmindDetectionSourceSeverity),
        Some(&CommonValue::Text(EventText::new("8.5").unwrap()))
    );
}
#[test]
fn every_documented_export_layout_uses_its_own_original_field_names() {
    for (name, bytes, count) in [
        (
            "api.json",
            include_bytes!("../../../testkit/fixtures/parser-guardduty/source/api.json").as_slice(),
            2,
        ),
        (
            "cli.json",
            include_bytes!("../../../testkit/fixtures/parser-guardduty/source/cli.json").as_slice(),
            1,
        ),
        (
            "eventbridge.json",
            include_bytes!("../../../testkit/fixtures/parser-guardduty/source/eventbridge.json")
                .as_slice(),
            1,
        ),
    ] {
        irmind_testkit::run_source_mapping_contract(
            Arc::new(irmind_mod_parser_guardduty::GuardDutySourceDecoder),
            Arc::new(GuardDutyMapping::new().unwrap()),
            name,
            bytes,
            count,
        )
        .unwrap();
    }
}
