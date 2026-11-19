use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{EntityRole, EventCategory, EventType};
use irmind_mod_parser_github_audit::GitHubAuditSourceDecoder;

const STREAM: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-github-audit/source/stream.ndjson");
const CSV: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-github-audit/source/export.csv");

#[test]
fn declarative_mapping_passes_the_shared_contract_for_both_encodings() {
    for (name, bytes, expected) in [("stream.ndjson", STREAM, 4), ("export.csv", CSV, 2)] {
        irmind_testkit::run_source_mapping_contract(
            Arc::new(GitHubAuditSourceDecoder),
            Arc::new(GitHubAuditMapping::new().unwrap()),
            name,
            bytes,
            expected,
        )
        .unwrap();
    }
}

#[test]
fn roles_and_operation_classification_use_only_native_audit_fields() {
    let mapper = GitHubAuditMapping::new().unwrap();
    let source = SourceReferenceV1::file("stream.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut bytes = STREAM;
    let mut rows = Vec::new();
    GitHubAuditSourceDecoder
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
                record.inspect(|row| rows.push(mapper.map(row).unwrap().into_record()));
                Ok(())
            },
        )
        .unwrap();
    assert!(
        rows[0]
            .common
            .event()
            .categories()
            .contains(EventCategory::File)
    );
    assert!(rows[0].common.event().types().contains(EventType::Access));
    assert!(
        rows[1]
            .common
            .event()
            .categories()
            .contains(EventCategory::Configuration)
    );
    assert!(
        rows[2]
            .common
            .event()
            .categories()
            .contains(EventCategory::Iam)
    );
    for (record, role, value) in [
        (0, EntityRole::Actor, "synthetic-operator"),
        (0, EntityRole::Source, "203.0.113.77"),
        (0, EntityRole::Target, "synthetic-lab/example"),
        (2, EntityRole::Target, "synthetic-contributor"),
    ] {
        assert!(
            rows[record]
                .common
                .observations()
                .values()
                .iter()
                .any(|obs| obs.role() == role && obs.entity().value() == value)
        );
    }
    assert!(rows[3].common.event().categories().iter().next().is_none());
    assert!(
        rows[3]
            .indexed
            .record
            .text
            .contains("original-field-preserved")
    );
}
