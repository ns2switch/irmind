use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
#[test]
fn network_roles_and_unknown_action_are_preserved() {
    let bytes = include_bytes!("../../../testkit/fixtures/parser-vpc-flow/source/custom.log");
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_vpc_flow::VpcFlowSourceDecoder),
        Arc::new(CloudFlowMapping::aws().unwrap()),
        "custom.log",
        bytes,
        4,
    )
    .unwrap();
    let reference = SourceReferenceV1::file("custom.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    irmind_mod_parser_vpc_flow::VpcFlowSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes.as_slice(),
            },
            &mut |r| {
                r.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    let mapper = CloudFlowMapping::aws().unwrap();
    for (row, outcome) in rows.iter().zip([
        irmind_domain::EventOutcome::Success,
        irmind_domain::EventOutcome::Failure,
        irmind_domain::EventOutcome::Unknown,
        irmind_domain::EventOutcome::Unknown,
    ]) {
        let output = mapper.map(row).unwrap();
        assert_eq!(output.partition().host(), "i-synthetic-1");
        let projection = output.into_record();
        assert_eq!(projection.common.event().outcome(), outcome);
        assert!(
            projection
                .common
                .event()
                .categories()
                .contains(irmind_domain::EventCategory::Network)
        );
    }
    let projection = mapper.map(&rows[0]).unwrap().into_record();
    for (role, value) in [
        (irmind_domain::EntityRole::Source, "203.0.113.77"),
        (irmind_domain::EntityRole::Destination, "192.0.2.10"),
    ] {
        assert!(
            projection
                .common
                .observations()
                .values()
                .iter()
                .any(|o| o.role() == role && o.entity().value() == value)
        );
    }
}

#[test]
fn azure_and_gcp_outcomes_follow_native_fields_and_missing_is_unknown() {
    type Case<'a> = (
        &'a dyn SourceDecoder,
        CloudFlowMapping,
        &'a str,
        &'a [u8],
        &'a [irmind_domain::EventOutcome],
    );
    let cases: [Case<'_>; 3] = [
        (
            &irmind_mod_parser_azure_flow::AzureFlowSourceDecoder,
            CloudFlowMapping::azure().unwrap().remove(0),
            "vnet.json",
            include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/vnet.json"),
            &[
                irmind_domain::EventOutcome::Success,
                irmind_domain::EventOutcome::Failure,
            ],
        ),
        (
            &irmind_mod_parser_azure_flow::AzureFlowSourceDecoder,
            CloudFlowMapping::azure().unwrap().remove(1),
            "nsg-v2.json",
            include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/nsg-v2.json"),
            &[
                irmind_domain::EventOutcome::Success,
                irmind_domain::EventOutcome::Failure,
            ],
        ),
        (
            &irmind_mod_parser_gcp_flow::GcpFlowSourceDecoder,
            CloudFlowMapping::gcp().unwrap(),
            "gcp.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-gcp-flow/source/events.ndjson"),
            &[
                irmind_domain::EventOutcome::Unknown,
                irmind_domain::EventOutcome::Failure,
                irmind_domain::EventOutcome::Unknown,
            ],
        ),
    ];
    for (decoder, mapper, name, bytes, expected) in cases {
        assert_outcomes(decoder, &mapper, name, bytes, expected);
    }
}
fn assert_outcomes(
    decoder: &dyn SourceDecoder,
    mapper: &CloudFlowMapping,
    name: &str,
    mut bytes: &[u8],
    expected: &[irmind_domain::EventOutcome],
) {
    let reference = SourceReferenceV1::file(name).unwrap();
    let cancel = CancellationToken::new();
    let mut seen = 0;
    decoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes,
            },
            &mut |r| {
                r.inspect(|r| {
                    let output = mapper.map(r).unwrap();
                    let projection = output.into_record();
                    assert_eq!(projection.common.event().outcome(), expected[seen]);
                    assert!(
                        projection
                            .common
                            .observations()
                            .values()
                            .iter()
                            .any(|o| o.role() == irmind_domain::EntityRole::Source
                                && o.entity().value() == "203.0.113.77")
                    );
                    assert!(
                        projection
                            .common
                            .observations()
                            .values()
                            .iter()
                            .any(|o| o.role() == irmind_domain::EntityRole::Destination
                                && o.entity().value() == "192.0.2.10")
                    );
                    seen += 1;
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(seen, expected.len());
}

#[test]
fn unknown_azure_versions_do_not_interpret_lookalike_columns() {
    let mut bytes =
        include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/future.ndjson")
            .as_slice();
    let reference = SourceReferenceV1::file("future.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mapper = CloudFlowMapping::azure().unwrap().remove(0);
    irmind_mod_parser_azure_flow::AzureFlowSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes,
            },
            &mut |r| {
                r.inspect(|r| {
                    let projection = mapper.map(r).unwrap().into_record();
                    assert_eq!(
                        projection.common.event().outcome(),
                        irmind_domain::EventOutcome::Unknown
                    );
                    assert!(projection.common.observations().values().is_empty());
                    assert!(
                        projection
                            .common
                            .context()
                            .get(irmind_domain::CommonField::CloudAccountId)
                            .is_none()
                    );
                    assert!(
                        projection
                            .common
                            .event()
                            .types()
                            .contains(irmind_domain::EventType::Info)
                    );
                    assert!(projection.indexed.record.text.contains("flowLogVersion"));
                });
                Ok(())
            },
        )
        .unwrap();
}
