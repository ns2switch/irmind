//! Release-only diagnostic of the production normalized-row accounting.
#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1};
use irmind_app::{SourceDecoder, SourceMapper};

#[test]
#[ignore = "manual optimized compact-source expansion diagnostic"]
fn compact_flow_normalized_expansion() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Run this diagnostic with --release");
    }
    let fixture =
        include_bytes!("../../../../../testkit/fixtures/parser-vpc-flow/source/custom.log");
    let mut lines = fixture.split_inclusive(|b| *b == b'\n');
    let mut bytes = lines.next().unwrap().to_vec();
    let source_row = lines.next().unwrap();
    bytes.extend_from_slice(source_row);
    let normalized = measure(
        &irmind_mod_parser_vpc_flow::VpcFlowSourceDecoder,
        &irmind_mod_mapping_cloud_flow::CloudFlowMapping::aws().unwrap(),
        &bytes,
    );
    println!(
        "NORMALIZED_EXPANSION source=vpc-custom source_row_bytes={} normalized_row_bytes={} ratio={:.3}",
        source_row.len(),
        normalized,
        ratio(normalized, source_row.len())
    );
    assert!(normalized > source_row.len() as u64 * 16);
    for (name, decoder, mapper, bytes) in cases() {
        let normalized = measure(decoder, &mapper, bytes);
        println!(
            "NORMALIZED_EXPANSION source={name} source_bytes={} normalized_bytes={normalized} ratio={:.3}",
            bytes.len(),
            ratio(normalized, bytes.len())
        );
    }
    Ok(())
}
fn ratio(normalized: u64, raw: usize) -> f64 {
    f64::from(u32::try_from(normalized).unwrap()) / f64::from(u32::try_from(raw).unwrap())
}
type Case = (
    &'static str,
    &'static dyn SourceDecoder,
    irmind_mod_mapping_cloud_flow::CloudFlowMapping,
    &'static [u8],
);
fn cases() -> Vec<Case> {
    use irmind_mod_mapping_cloud_flow::CloudFlowMapping as Mapper;
    vec![
        (
            "vpc-default",
            &irmind_mod_parser_vpc_flow::VpcFlowSourceDecoder,
            Mapper::aws().unwrap(),
            include_bytes!("../../../../../testkit/fixtures/parser-vpc-flow/source/default.log"),
        ),
        (
            "azure-vnet",
            &irmind_mod_parser_azure_flow::AzureFlowSourceDecoder,
            Mapper::azure().unwrap().remove(0),
            include_bytes!("../../../../../testkit/fixtures/parser-azure-flow/source/vnet.json"),
        ),
        (
            "azure-nsg",
            &irmind_mod_parser_azure_flow::AzureFlowSourceDecoder,
            Mapper::azure().unwrap().remove(1),
            include_bytes!("../../../../../testkit/fixtures/parser-azure-flow/source/nsg-v2.json"),
        ),
        (
            "gcp",
            &irmind_mod_parser_gcp_flow::GcpFlowSourceDecoder,
            Mapper::gcp().unwrap(),
            include_bytes!("../../../../../testkit/fixtures/parser-gcp-flow/source/events.ndjson"),
        ),
    ]
}
fn measure(decoder: &dyn SourceDecoder, mapper: &dyn SourceMapper, mut bytes: &[u8]) -> u64 {
    let hash_bytes = irmind_app::sha256(bytes);
    let hash = irmind_domain::EvidenceHash::parse(&irmind_app::hex(&hash_bytes)).unwrap();
    let source = SourceReferenceV1::file("compact-flow.log").unwrap();
    let cancel = CancellationToken::new();
    let mut normalized = 0;
    decoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: hash_bytes,
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes,
            },
            &mut |tainted| {
                tainted.inspect(|record| {
                    let output = mapper.map(record).unwrap();
                    let row = RecordRow::from_mapping(
                        &output,
                        tainted.provenance(),
                        decoder.identity(),
                        &hash,
                        "0".repeat(64),
                    )
                    .unwrap();
                    let mut counter = EncodedSize(1);
                    serde_json::to_writer(&mut counter, &row).unwrap();
                    normalized += counter.0;
                });
                Ok(())
            },
        )
        .unwrap();
    normalized
}
