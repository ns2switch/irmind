use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{CommonField, CommonValue, EntityRole, EventCategory, EventOutcome};
use irmind_mod_parser_route53::Route53SourceDecoder;

const ROWS: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-route53/source/queries.ndjson");

#[test]
fn contract_covers_dns_fields_original_answers_and_unknown_types() {
    let mapper = Arc::new(Route53Mapping::new().unwrap());
    irmind_testkit::run_source_mapping_contract(
        Arc::new(Route53SourceDecoder),
        mapper.clone(),
        "queries.ndjson",
        ROWS,
        3,
    )
    .unwrap();
    let source = SourceReferenceV1::file("queries.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut index = 0;
    Route53SourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(ROWS),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut &ROWS[..],
            },
            &mut |record| {
                record.inspect(|row| {
                    let mapped = mapper.map(row).unwrap().into_record();
                    assert!(
                        mapped
                            .common
                            .event()
                            .categories()
                            .contains(EventCategory::Network)
                    );
                    assert_eq!(
                        mapped.common.event().outcome(),
                        [
                            EventOutcome::Success,
                            EventOutcome::Failure,
                            EventOutcome::Unknown
                        ][index]
                    );
                    assert!(mapped.common.observations().values().iter().any(|obs| {
                        obs.role() == EntityRole::Source
                            && obs.entity().value()
                                == ["203.0.113.77", "2001:db8::47", "192.0.2.8"][index]
                    }));
                    if index == 0 {
                        assert_eq!(
                            mapped.common.context().get(CommonField::SourcePort),
                            Some(&CommonValue::Unsigned(51390))
                        );
                        assert!(mapped.indexed.record.text.contains("192.0.2.31"));
                    }
                    if index == 2 {
                        assert!(mapped.indexed.record.text.contains("TYPE65000"));
                    }
                    index += 1;
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(index, 3);
}
