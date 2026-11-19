use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{CommonField, CommonValue, EntityRole, EventOutcome, EventText};
use irmind_mod_parser_iis_w3c::IisW3cSourceDecoder;

const LOG: &[u8] = include_bytes!("../../../testkit/fixtures/parser-iis-w3c/source/access.log");

#[test]
fn mapping_contract_keeps_http_roles_query_bytes_and_unknown_status() {
    let mapper = Arc::new(IisW3cMapping::new().unwrap());
    irmind_testkit::run_source_mapping_contract(
        Arc::new(IisW3cSourceDecoder),
        mapper.clone(),
        "access.log",
        LOG,
        3,
    )
    .unwrap();
    let reference = SourceReferenceV1::file("access.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    IisW3cSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
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
        rows[0].common.context().get(CommonField::UrlQuery),
        Some(&CommonValue::Text(
            EventText::new("command=%2522%253Bkeep").unwrap()
        ))
    );
    assert!(
        rows[0]
            .common
            .observations()
            .values()
            .iter()
            .any(|reference| reference.role() == EntityRole::Destination
                && reference.entity().value() == "192.0.2.14")
    );
    assert!(rows[2].indexed.record.text.contains("original-custom"));
}
