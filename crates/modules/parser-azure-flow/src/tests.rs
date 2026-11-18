use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
#[test]
fn native_vnet_and_nsg_versions_keep_original_tuples() {
    for (name, bytes, count) in [
        (
            "vnet.json",
            include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/vnet.json")
                .as_slice(),
            2,
        ),
        (
            "vnet-v5.json",
            include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/vnet-v5.json")
                .as_slice(),
            2,
        ),
        (
            "nsg-v1.json",
            include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/nsg-v1.json")
                .as_slice(),
            2,
        ),
        (
            "nsg-v2.json",
            include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/nsg-v2.json")
                .as_slice(),
            2,
        ),
        (
            "future.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/future.ndjson")
                .as_slice(),
            1,
        ),
    ] {
        irmind_testkit::run_log_parser_contract(
            &AzureFlowParser,
            &AzureFlowSourceDecoder,
            name,
            bytes,
            count,
            None,
        )
        .unwrap();
    }
}
#[test]
fn millisecond_times_and_unknown_versions_are_not_guessed() {
    let mut bytes =
        include_bytes!("../../../testkit/fixtures/parser-azure-flow/source/vnet.ndjson").as_slice();
    let reference = SourceReferenceV1::file("source.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = AzureFlowSourceDecoder
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
                r.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(
        rows[0].timestamp().unwrap().instant().unix_micros(),
        1_767_225_600_123_000
    );
    assert!(rows.iter().all(|r| r.origin().offset().is_none()));
    assert_eq!(
        rows[0].timestamp().unwrap().precision(),
        irmind_domain::TimePrecision::Millisecond
    );
}
#[test]
fn filename_is_not_a_format_proof() {
    use irmind_app::LogParser;
    assert!(AzureFlowParser.detect("vnet.json", b"unrelated").is_none());
}
