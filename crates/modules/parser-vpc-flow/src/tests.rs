use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use std::io::Write;
const CUSTOM: &[u8] = include_bytes!("../../../testkit/fixtures/parser-vpc-flow/source/custom.log");
#[test]
fn original_header_and_cloudwatch_contracts() {
    for (name, bytes, count) in [
        ("custom.log", CUSTOM, 4),
        (
            "default.log",
            include_bytes!("../../../testkit/fixtures/parser-vpc-flow/source/default.log")
                .as_slice(),
            1,
        ),
        (
            "cloudwatch.json",
            include_bytes!("../../../testkit/fixtures/parser-vpc-flow/source/cloudwatch.json")
                .as_slice(),
            4,
        ),
    ] {
        irmind_testkit::run_log_parser_contract(
            &VpcFlowParser,
            &VpcFlowSourceDecoder,
            name,
            bytes,
            count,
            None,
        )
        .unwrap();
    }
}
#[test]
fn headerless_layout_is_never_selected_automatically() {
    use irmind_app::modules::{ModuleConfig, ModuleRegistry, ParserChoice};
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(VpcFlowParser), &ModuleConfig::new())
        .unwrap();
    let bytes = include_bytes!("../../../testkit/fixtures/parser-vpc-flow/source/default.log");
    assert!(matches!(
        registry.detect_parser("unknown.log", bytes),
        ParserChoice::NeedsAnalyst(_)
    ));
    assert_eq!(
        VpcFlowParser.detect("unknown.log", CUSTOM).unwrap().value(),
        98
    );
    assert!(VpcFlowParser.detect("vpc.log", b"unrelated").is_none());
}
fn decode(
    mut bytes: &[u8],
) -> (
    irmind_app::ParseReport,
    Vec<irmind_app::source_mapping::SourceRecordV1>,
) {
    let reference = SourceReferenceV1::file("unknown.bin").unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let report = VpcFlowSourceDecoder
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
                r.inspect(|r| records.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, records)
}
#[test]
fn invalid_line_keeps_the_next_record_and_real_offset() {
    let newline = CUSTOM.iter().position(|b| *b == b'\n').unwrap() + 1;
    let mut bytes = CUSTOM[..newline].to_vec();
    bytes.extend_from_slice(b"invalid \"quote\n");
    bytes.extend_from_slice(&CUSTOM[newline..]);
    let (report, records) = decode(&bytes);
    assert_eq!((report.accepted, report.rejected), (4, 1));
    assert_eq!(records[0].origin().record(), 0);
    assert_eq!(records[0].annotations().members()[0].ordinal, 1);
    assert_eq!(records[0].origin().offset(), Some((newline + 15) as u64));
}
#[test]
fn gzip_checks_integrity_and_never_invents_compressed_record_offsets() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(CUSTOM).unwrap();
    let mut bytes = encoder.finish().unwrap();
    let (report, records) = decode(&bytes);
    assert_eq!((report.accepted, report.rejected), (4, 0));
    assert!(records.iter().all(|r| r.origin().offset().is_none()));
    assert_eq!(
        VpcFlowParser.detect("opaque.bin", &bytes).unwrap().value(),
        98
    );
    let end = bytes.len() - 8;
    bytes[end] ^= 1;
    let reference = SourceReferenceV1::file("bad.gz").unwrap();
    let cancel = CancellationToken::new();
    assert!(
        VpcFlowSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &reference,
                        evidence_hash: irmind_app::sha256(&bytes),
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel
                    },
                    reader: &mut bytes.as_slice()
                },
                &mut |_| Ok(())
            )
            .is_err()
    );
}

#[test]
fn canonical_records_and_rejections_are_independent_of_worker_count() {
    irmind_testkit::run_decode_budget_contract(
        &VpcFlowSourceDecoder,
        "custom.log",
        include_bytes!("../../../testkit/fixtures/parser-vpc-flow/source/custom.log"),
    )
    .unwrap();
}

#[test]
fn missing_start_uses_explicit_end_without_inventing_a_time() {
    let bytes = b"version srcaddr dstaddr start end\n2 203.0.113.77 192.0.2.10 - 1767225601\n";
    let (report, records) = decode(bytes);
    assert_eq!(report.accepted, 1);
    assert_eq!(
        records[0].timestamp().unwrap().instant().unix_micros(),
        1_767_225_601_000_000
    );
}
