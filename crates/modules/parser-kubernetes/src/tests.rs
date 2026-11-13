use super::*;
use irmind_app::{
    CancellationToken, ParseReport, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1,
    },
};
use irmind_domain::{ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding};
use std::io::Cursor;
const EVENT: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/event.ndjson");
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
    workers: usize,
    cancel: &CancellationToken,
) -> Result<(ParseReport, Vec<SourceRecordV1>), AppError> {
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let mut rows = Vec::new();
    let report = KubernetesSourceDecoder.decode_with_budget(
        DecodeInput::Reader(SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cluster_context: context,
                cancel,
            },
            reader: &mut Cursor::new(bytes),
        }),
        DecodeBudget::new(
            std::num::NonZeroUsize::new(workers).unwrap(),
            16 * 1024 * 1024,
        ),
        &mut |row| {
            row.inspect(|r| rows.push(r.clone()));
            Ok(())
        },
    )?;
    Ok((report, rows))
}
#[test]
fn original_bodies_nanoseconds_cluster_and_offsets_are_preserved_without_classification() {
    let context = context();
    let (report, rows) = decode(EVENT, Some(&context), 1, &CancellationToken::new()).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(
        rows[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-01T00:00:00.123456789Z"
    );
    assert_eq!(
        rows[0].cluster_identity(),
        Some(context.bindings()[0].identity())
    );
    assert_eq!(rows[0].origin().offset(), Some(0));
    assert!(rows[0].fields().field("requestObject").is_some());
    assert!(rows[0].fields().field("event.outcome").is_none());
    assert_eq!(
        KubernetesParser::default()
            .detect("wrong.txt", EVENT)
            .unwrap()
            .value(),
        98
    );
}
#[test]
fn cluster_is_never_inferred_from_machine_or_file_name() {
    let error = decode(EVENT, None, 1, &CancellationToken::new())
        .err()
        .unwrap();
    assert!(error.to_string().contains("cluster"));
    assert!(
        KubernetesParser::default()
            .cluster_context_requirement("cluster-a.log", EVENT)
            .unwrap()
            .unwrap()
            .required()
    );
}
#[test]
fn rejected_rows_do_not_drop_later_records_and_worker_counts_preserve_commitments() {
    let mut bytes = b"{\"apiVersion\":\"audit.k8s.io/v1\",\"kind\":\"Event\"}\n".to_vec();
    bytes.extend_from_slice(EVENT);
    bytes.push(b'\n');
    bytes.extend_from_slice(EVENT);
    let context = context();
    let mut reference = None;
    for workers in [1, 2, 4] {
        let (report, rows) =
            decode(&bytes, Some(&context), workers, &CancellationToken::new()).unwrap();
        assert_eq!((report.accepted, report.rejected), (2, 1));
        assert_eq!(
            rows[0].origin().offset(),
            Some(u64::try_from(bytes.len() - EVENT.len() * 2 - 1).unwrap())
        );
        let mut canonical = Vec::new();
        for row in rows {
            row.feed_canonical(&mut |part| canonical.extend_from_slice(part));
        }
        let hash = irmind_app::sha256(&canonical);
        if let Some(expected) = reference {
            assert_eq!(hash, expected);
        } else {
            reference = Some(hash);
        }
    }
}
#[test]
fn a_cancelled_decode_never_emits_a_record() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        decode(EVENT, Some(&context()), 1, &cancel),
        Err(AppError::Cancelled)
    ));
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
        let report = KubernetesSourceDecoder
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

struct ConfirmedDecoder(SourceClusterContext);
impl SourceDecoder for ConfirmedDecoder {
    fn identity(&self) -> irmind_app::ParserIdentity<'_> {
        KubernetesSourceDecoder.identity()
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(irmind_domain::Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        KubernetesSourceDecoder.decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    cluster_context: Some(&self.0),
                    ..input.metadata
                },
                reader: input.reader,
            },
            emit,
        )
    }
}
#[test]
fn shared_decoder_contract_uses_only_the_explicitly_confirmed_context() {
    irmind_testkit::run_log_parser_contract(
        &KubernetesParser::default(),
        &ConfirmedDecoder(context()),
        "synthetic.ndjson",
        EVENT,
        1,
        None,
    )
    .unwrap();
}
