use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
use irmind_domain::{ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding};
use serde_json::{Value, json};
const EKS: &[u8] = include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/eks.json");
const AKS: &[u8] = include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/aks.json");
const EKS_ID: &str = "arn:aws:eks:us-east-1:111122223333:cluster/synthetic-cluster";
const AKS_ID: &str = "/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/synthetic/providers/Microsoft.ContainerService/managedClusters/synthetic-cluster";
fn context(provider: ClusterProvider, id: &str, confirmed: bool) -> SourceClusterContext {
    SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(
            ClusterIdentity::try_new(provider, id).unwrap(),
            if confirmed {
                ClusterContextBasis::ConfirmedSource
            } else {
                ClusterContextBasis::Command
            },
            confirmed.then_some(id),
        )
        .unwrap(),
    ])
    .unwrap()
}
fn decode(
    bytes: &[u8],
    context: Option<&SourceClusterContext>,
) -> Result<(irmind_app::ParseReport, Vec<SourceRecordV1>), AppError> {
    let source = SourceReferenceV1::file("untrusted-name.bin").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = KubernetesSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cluster_context: context,
                cancel: &cancel,
            },
            reader: &mut std::io::Cursor::new(bytes),
        },
        &mut |row| {
            row.inspect(|r| rows.push(r.clone()));
            Ok(())
        },
    )?;
    Ok((report, rows))
}
#[test]
fn managed_transports_preserve_outer_rows_decoded_fields_time_and_real_offsets() {
    for (bytes, provider, id, format, key) in [
        (EKS, ClusterProvider::Eks, EKS_ID, "eks-audit", "events"),
        (AKS, ClusterProvider::Aks, AKS_ID, "aks-audit", "records"),
    ] {
        let context = context(provider, id, provider == ClusterProvider::Aks);
        let (report, rows) = decode(bytes, Some(&context)).unwrap();
        assert_eq!((report.accepted, report.rejected), (2, 0));
        assert_eq!(
            KubernetesParser::default()
                .detect("arbitrary.ext", bytes)
                .unwrap()
                .value(),
            98
        );
        let original: Value = serde_json::from_slice(bytes).unwrap();
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.origin().record(), i as u64);
            assert_eq!(row.format().id(), format);
            assert_eq!(row.cluster_identity().unwrap().id(), id);
            let transport = row.fields().field("transport").unwrap();
            let raw = serde_json::to_vec(&original[key][i]).unwrap();
            let parsed = irmind_app::source_mapping::json::decode_json_fields(
                &raw,
                irmind_app::source_mapping::json::SourceJsonLimits::default(),
            )
            .unwrap();
            assert_eq!(transport, &parsed);
            let offset = usize::try_from(row.origin().offset().unwrap()).unwrap();
            assert_eq!(bytes[offset], b'{');
            assert!(
                row.fields()
                    .field("audit_event")
                    .unwrap()
                    .field("requestObject")
                    .is_some()
            );
        }
    }
}
#[test]
fn aks_claims_are_suggested_but_never_silently_accepted() {
    let parser = KubernetesParser::default();
    let requirement = parser
        .cluster_context_requirement("export.json", AKS)
        .unwrap()
        .unwrap();
    assert_eq!(requirement.source_claims()[0].id(), AKS_ID);
    assert!(matches!(
        decode(AKS, None),
        Err(AppError::ParserClusterContextRequired { .. })
    ));
    let wrong = context(
        ClusterProvider::Aks,
        &AKS_ID.replace("synthetic-cluster", "other"),
        false,
    );
    assert!(decode(AKS, Some(&wrong)).is_err());
    let wrong_provider = context(ClusterProvider::Kubernetes, "urn:k8s:synthetic", false);
    assert!(decode(EKS, Some(&wrong_provider)).is_err());
}
#[test]
fn get_log_events_requires_an_explicit_eks_identity_not_a_machine_default() {
    let requirement = KubernetesParser::default()
        .cluster_context_requirement("export.json", EKS)
        .unwrap()
        .unwrap();
    assert!(requirement.required());
    assert!(requirement.source_claims().is_empty());
    assert!(matches!(
        decode(EKS, None),
        Err(AppError::ParserClusterContextRequired { .. })
    ));
    let manual = context(ClusterProvider::Eks, EKS_ID, false);
    assert_eq!(decode(EKS, Some(&manual)).unwrap().0.accepted, 2);
}
#[test]
fn invalid_embedded_json_is_rejected_without_hiding_the_next_transport_record() {
    let mut export: Value = serde_json::from_slice(EKS).unwrap();
    export["events"][0]["message"] = json!("{invalid");
    let bytes = serde_json::to_vec(&export).unwrap();
    let manual = context(ClusterProvider::Eks, EKS_ID, false);
    let (report, rows) = decode(&bytes, Some(&manual)).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(rows[0].origin().record(), 0);
    assert_eq!(rows[0].annotations().members()[0].ordinal, 1);
    assert!(report.samples.iter().all(|s| s.len() <= 256));
}
#[test]
fn cloudwatch_and_monitor_inputs_pass_the_shared_taint_and_cancellation_contract() {
    for (bytes, provider, id) in [
        (EKS, ClusterProvider::Eks, EKS_ID),
        (AKS, ClusterProvider::Aks, AKS_ID),
    ] {
        let context = context(provider, id, false);
        let parser = KubernetesParser::default()
            .with_cluster_context(&context)
            .unwrap();
        irmind_testkit::run_log_parser_contract(
            parser.as_ref(),
            &ConfirmedDecoder(context),
            "export.json",
            bytes,
            2,
            None,
        )
        .unwrap();
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
    ) -> Result<irmind_app::ParseReport, AppError> {
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
fn later_cluster_claims_require_confirmation_and_conflicting_aliases_are_rejected() {
    let mut export: Value = serde_json::from_slice(AKS).unwrap();
    let second_id = AKS_ID.replace("synthetic-cluster", "other-cluster");
    export["records"][1]["resourceId"] = json!(second_id);
    let bytes = serde_json::to_vec(&export).unwrap();
    let confirmed = context(ClusterProvider::Aks, AKS_ID, true);
    let error = decode(&bytes, Some(&confirmed));
    assert!(
        matches!(error, Err(AppError::ParserClusterContextRequired { requirement, .. }) if requirement.source_claims().len() == 2)
    );
    export["records"][1]["resourceId"] = json!(AKS_ID);
    export["records"][0]["ResourceId"] = json!(second_id);
    let manual = context(ClusterProvider::Aks, AKS_ID, false);
    let (report, rows) = decode(&serde_json::to_vec(&export).unwrap(), Some(&manual)).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(rows[0].annotations().members()[0].ordinal, 1);
}
