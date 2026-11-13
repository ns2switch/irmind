use super::*;
use irmind_app::{
    CancellationToken, ParseReport, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
use irmind_domain::{ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding};
use std::io::Cursor;
const EVENT: &[u8] = include_bytes!("../../../testkit/fixtures/parser-falco/source/event.ndjson");
fn context() -> SourceClusterContext {
    SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(
            ClusterIdentity::try_new(ClusterProvider::Kubernetes, "urn:k8s:synthetic").unwrap(),
            ClusterContextBasis::Analyst,
            None,
        )
        .unwrap(),
    ])
    .unwrap()
}
fn decode(
    bytes: &[u8],
    context: Option<&SourceClusterContext>,
) -> Result<(ParseReport, Vec<SourceRecordV1>), AppError> {
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = FalcoSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cluster_context: context,
                cancel: &cancel,
            },
            reader: &mut Cursor::new(bytes),
        },
        &mut |row| {
            row.inspect(|r| rows.push(r.clone()));
            Ok(())
        },
    )?;
    Ok((report, rows))
}
#[test]
fn a_falco_rule_is_original_data_not_a_confirmed_finding() {
    let context = context();
    let (report, rows) = decode(EVENT, Some(&context)).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(
        rows[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-01T00:00:00.123456789Z"
    );
    assert!(rows[0].fields().field("confirmed").is_none());
    assert!(
        rows[0]
            .fields()
            .field("output_fields")
            .unwrap()
            .field("proc.pid")
            .is_some()
    );
    assert_eq!(
        rows[0].cluster_identity(),
        Some(context.bindings()[0].identity())
    );
    assert_eq!(
        FalcoParser::default()
            .detect("wrong.csv", EVENT)
            .unwrap()
            .value(),
        98
    );
}
#[test]
fn kubernetes_requires_context_but_plain_host_detections_do_not_invent_it() {
    assert!(matches!(
        decode(EVENT, None),
        Err(AppError::ParserClusterContextRequired { .. })
    ));
    let plain = br#"{"time":"2026-11-01T00:00:00Z","rule":"Synthetic host shell","priority":"Warning","output_fields":{"proc.name":"sh"}}"#;
    let (report, rows) = decode(plain, None).unwrap();
    assert_eq!(report.accepted, 1);
    assert!(rows[0].cluster_identity().is_none());
    assert!(
        !FalcoParser::default()
            .cluster_context_requirement("synthetic.log", plain)
            .unwrap()
            .unwrap()
            .required()
    );
    assert!(
        FalcoParser::default()
            .cluster_context_requirement("synthetic.log", EVENT)
            .unwrap()
            .unwrap()
            .required()
    );
}
#[test]
fn a_later_kubernetes_record_cannot_bypass_context_confirmation() {
    let mut bytes = br#"{"time":"2026-11-01T00:00:00Z","rule":"Synthetic host shell","priority":"Warning","output_fields":{}}"#.to_vec();
    bytes.push(b'\n');
    bytes.extend_from_slice(EVENT);
    assert!(matches!(
        decode(&bytes, None),
        Err(AppError::ParserClusterContextRequired { .. })
    ));
}
#[test]
fn malformed_record_is_counted_and_next_valid_record_keeps_its_real_offset() {
    let mut bytes = b"{\"rule\":\"missing fields\"}\n".to_vec();
    let offset = bytes.len();
    bytes.extend_from_slice(EVENT);
    let (report, rows) = decode(&bytes, Some(&context())).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(
        rows[0].origin().offset(),
        Some(u64::try_from(offset).unwrap())
    );
    assert!(report.samples.iter().all(|sample| sample.len() <= 256));
}

#[test]
fn oversized_first_lines_are_bounded_and_later_records_keep_real_offsets() {
    use std::io::Read as _;
    for size in [5u64, 50, 200].map(|mib| mib * 1024 * 1024) {
        let context = context();
        let cancel = CancellationToken::new();
        let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
        let mut tail = vec![b'\n'];
        tail.extend_from_slice(EVENT);
        let mut reader = std::io::repeat(b'x').take(size).chain(Cursor::new(tail));
        let mut offset = None;
        let report = FalcoSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: [8; 32],
                        time_context: None,
                        cluster_context: Some(&context),
                        cancel: &cancel,
                    },
                    reader: &mut reader,
                },
                &mut |row| {
                    row.inspect(|r| offset = r.origin().offset());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected), (1, 1));
        assert_eq!(offset, Some(size + 1));
        assert!(report.samples.iter().all(|sample| sample.len() <= 256));
    }
}

#[test]
fn host_only_falco_passes_the_shared_decoder_contract_without_a_fake_cluster() {
    let bytes = br#"{"time":"2026-11-01T00:00:00Z","rule":"Synthetic host shell","priority":"Warning","output_fields":{"proc.name":"sh"}}"#;
    irmind_testkit::run_log_parser_contract(
        &FalcoParser::default(),
        &FalcoSourceDecoder,
        "synthetic.ndjson",
        bytes,
        1,
        None,
    )
    .unwrap();
}
