use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{CommonField, CommonValue, EntityRole, EventOutcome};
use irmind_mod_parser_s3_access::S3AccessSourceDecoder;
use std::sync::Arc;

const LOG: &[u8] = include_bytes!("../../../testkit/fixtures/parser-s3-access/source/access.log");

#[test]
fn s3_mapping_preserves_status_and_measures_response_bytes_independently_of_object_size() {
    let mapper = Arc::new(S3AccessMapping::new().unwrap());
    irmind_testkit::run_source_mapping_contract(
        Arc::new(S3AccessSourceDecoder),
        mapper.clone(),
        "access.log",
        LOG,
        3,
    )
    .unwrap();
    let source = SourceReferenceV1::file("access.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    S3AccessSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(LOG),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut &LOG[..],
            },
            &mut |record| {
                record.inspect(|row| rows.push(mapper.map(row).unwrap().into_record()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(rows[0].common.event().outcome(), EventOutcome::Success);
    assert_eq!(rows[1].common.event().outcome(), EventOutcome::Failure);
    assert_eq!(rows[2].common.event().outcome(), EventOutcome::Unknown);
    assert_eq!(
        rows[1].common.context().get(CommonField::HttpResponseBytes),
        Some(&CommonValue::Unsigned(200))
    );
    assert!(
        rows[0]
            .common
            .observations()
            .values()
            .iter()
            .any(|reference| reference.role() == EntityRole::Target
                && reference.entity().value() == "synthetic-archive")
    );
    assert!(rows[2].indexed.record.text.contains("REST.FUTURE.EXAMPLE"));
}
