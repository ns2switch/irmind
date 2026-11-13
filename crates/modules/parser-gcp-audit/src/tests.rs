use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
use irmind_domain::{ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding};
const CLOUD: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-gcp-audit/source/event.ndjson");
const GKE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-gcp-audit/source/gke.ndjson");
fn decode(
    bytes: &[u8],
    context: Option<&SourceClusterContext>,
) -> Result<(irmind_app::ParseReport, Vec<SourceRecordV1>), AppError> {
    let reference = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let report = GcpAuditSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cluster_context: context,
                cancel: &cancel,
            },
            reader: &mut std::io::Cursor::new(bytes),
        },
        &mut |r| {
            r.inspect(|r| records.push(r.clone()));
            Ok(())
        },
    )?;
    Ok((report, records))
}
fn context(id: &str, basis: ClusterContextBasis) -> SourceClusterContext {
    let identity = ClusterIdentity::try_new(ClusterProvider::Gke, id).unwrap();
    SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(
            identity.clone(),
            basis,
            (basis == ClusterContextBasis::ConfirmedSource).then_some(id),
        )
        .unwrap(),
    ])
    .unwrap()
}
#[test]
fn cloud_audit_original_types_and_nanoseconds_survive_without_a_fake_cluster() {
    let (report, records) = decode(CLOUD, None).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(
        records[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-01T00:00:00.123456789Z"
    );
    assert!(records[0].cluster_identity().is_none());
    assert_eq!(records[0].origin().offset(), Some(0));
    assert!(
        records[0]
            .fields()
            .field("protoPayload")
            .unwrap()
            .field("request")
            .is_some()
    );
    assert_eq!(
        GcpAuditParser::default()
            .detect("untrusted.ext", CLOUD)
            .unwrap()
            .value(),
        98
    );
    assert!(
        GcpAuditParser::default()
            .cluster_context_requirement("source", CLOUD)
            .unwrap()
            .is_none()
    );
}
#[test]
fn gke_source_claim_requires_exact_confirmation_and_cannot_replace_another_cluster() {
    let requirement = GcpAuditParser::default()
        .cluster_context_requirement("source", GKE)
        .unwrap()
        .unwrap();
    assert!(requirement.required());
    let id = "projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster";
    let binding = context(id, ClusterContextBasis::ConfirmedSource);
    let (report, rows) = decode(GKE, Some(&binding)).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(
        rows[0].cluster_identity(),
        Some(binding.bindings()[0].identity())
    );
    assert!(matches!(
        decode(GKE, None),
        Err(AppError::ParserClusterContextRequired { .. })
    ));
    let wrong = context(
        "projects/synthetic-project/locations/us-central1/clusters/other",
        ClusterContextBasis::Command,
    );
    assert!(decode(GKE, Some(&wrong)).is_err());
}
#[test]
fn partial_labels_need_manual_context_and_each_remaining_claim_must_agree() {
    let raw = std::str::from_utf8(GKE).unwrap();
    let partial = raw.replace(
        "\"cluster_name\":\"synthetic-cluster\"",
        "\"synthetic_attribute\":\"not-an-identity\"",
    );
    let binding = context(
        "projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
        ClusterContextBasis::Command,
    );
    assert_eq!(
        decode(partial.as_bytes(), Some(&binding))
            .unwrap()
            .0
            .accepted,
        1
    );
    let confirmed = context(
        "projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
        ClusterContextBasis::ConfirmedSource,
    );
    assert!(decode(partial.as_bytes(), Some(&confirmed)).is_err());
    assert!(
        decode(
            partial
                .replace("synthetic-project", "other-project")
                .as_bytes(),
            Some(&binding)
        )
        .is_err()
    );
}
#[test]
fn ordinary_cloud_records_pass_the_shared_contract_and_malformed_rows_do_not_hide_later_data() {
    irmind_testkit::run_log_parser_contract(
        &GcpAuditParser::default(),
        &GcpAuditSourceDecoder,
        "synthetic.ndjson",
        CLOUD,
        1,
        None,
    )
    .unwrap();
    let bytes = [b"{bad}\n".as_slice(), CLOUD].concat();
    let (report, records) = decode(&bytes, None).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(records[0].origin().offset(), Some(6));
}

#[test]
fn multiple_gke_claims_are_suggested_and_an_unseen_later_claim_requires_new_confirmation()
-> Result<(), &'static str> {
    let second = std::str::from_utf8(GKE)
        .unwrap()
        .replace("synthetic-cluster", "second-cluster");
    let bytes = [GKE, second.as_bytes()].concat();
    let requirement = GcpAuditParser::default()
        .cluster_context_requirement("source", &bytes)
        .unwrap()
        .unwrap();
    assert_eq!(requirement.source_claims().len(), 2);
    let first = context(
        "projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
        ClusterContextBasis::ConfirmedSource,
    );
    let Err(AppError::ParserClusterContextRequired { requirement, .. }) =
        decode(&bytes, Some(&first))
    else {
        return Err("another source claim must require confirmation");
    };
    assert_eq!(requirement.source_claims().len(), 2);
    let bindings = requirement
        .source_claims()
        .iter()
        .map(|identity| {
            SourceClusterBinding::try_new(
                identity.clone(),
                ClusterContextBasis::ConfirmedSource,
                Some(identity.id()),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        decode(
            &bytes,
            Some(&SourceClusterContext::try_new(bindings).unwrap())
        )
        .unwrap()
        .0
        .accepted,
        2
    );
    Ok(())
}
#[test]
fn oversized_first_line_cannot_consume_later_records() {
    use std::io::Read as _;
    for size in [5u64, 50, 200].map(|n| n * 1024 * 1024) {
        let mut reader = std::io::repeat(b'x')
            .take(size)
            .chain(std::io::Cursor::new([b"\n".as_slice(), CLOUD].concat()));
        let reference = SourceReferenceV1::file("synthetic.ndjson").unwrap();
        let cancel = CancellationToken::new();
        let mut offset = None;
        let report = GcpAuditSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &reference,
                        evidence_hash: [8; 32],
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut reader,
                },
                &mut |r| {
                    r.inspect(|r| offset = r.origin().offset());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected), (1, 1));
        assert_eq!(offset, Some(size + 1));
        assert!(report.samples.iter().all(|s| s.len() <= 256));
    }
}

#[test]
fn worker_counts_preserve_gke_and_cloud_canonical_records() {
    use irmind_app::source_mapping::{DecodeBudget, DecodeInput};
    for (fixture, context) in [
        (CLOUD, None),
        (
            GKE,
            Some(context(
                "projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
                ClusterContextBasis::Command,
            )),
        ),
    ] {
        let bytes = [fixture, fixture].concat();
        let reference = SourceReferenceV1::file("synthetic.ndjson").unwrap();
        let cancel = CancellationToken::new();
        let mut expected = None;
        for workers in [1, 2, 4] {
            let mut canonical = Vec::new();
            let report = GcpAuditSourceDecoder
                .decode_with_budget(
                    DecodeInput::Reader(SourceInput {
                        metadata: SourceMetadata {
                            source: &reference,
                            evidence_hash: irmind_app::sha256(&bytes),
                            time_context: None,
                            cluster_context: context.as_ref(),
                            cancel: &cancel,
                        },
                        reader: &mut std::io::Cursor::new(&bytes),
                    }),
                    DecodeBudget::new(
                        std::num::NonZeroUsize::new(workers).unwrap(),
                        32 * 1024 * 1024,
                    ),
                    &mut |record| {
                        record
                            .inspect(|r| r.feed_canonical(&mut |v| canonical.extend_from_slice(v)));
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!((report.accepted, report.rejected), (2, 0));
            let hash = irmind_app::sha256(&canonical);
            if let Some(expected) = expected {
                assert_eq!(hash, expected);
            } else {
                expected = Some(hash);
            }
        }
    }
}

#[test]
fn malformed_cluster_labels_reject_only_the_row_without_hiding_the_next_offset() {
    let bad = std::str::from_utf8(GKE)
        .unwrap()
        .replace("\"project_id\":\"synthetic-project\",", "")
        .replace(
            "\"location\":\"us-central1\"",
            "\"location\":\"../invalid\"",
        );
    assert_ne!(bad.as_bytes(), GKE);
    let mut bytes = bad.trim_end().as_bytes().to_vec();
    bytes.push(b'\n');
    let offset = bytes.len() as u64;
    bytes.extend_from_slice(GKE);
    let binding = context(
        "projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
        ClusterContextBasis::ConfirmedSource,
    );
    let (report, records) = decode(&bytes, Some(&binding)).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(records[0].origin().offset(), Some(offset));
    let requirement = GcpAuditParser::default()
        .cluster_context_requirement("synthetic.ndjson", &bytes)
        .unwrap()
        .unwrap();
    assert_eq!(
        requirement.source_claims(),
        &[binding.bindings()[0].identity().clone()]
    );
}
