use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{
    ClusterContextBasis, ClusterIdentity, ClusterProvider, CommonField, CommonValue, EventOutcome,
    SourceClusterBinding, SourceClusterContext,
};
const EKS: &[u8] = include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/eks.json");
const AKS: &[u8] = include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/aks.json");
fn context(provider: ClusterProvider) -> SourceClusterContext {
    let id = match provider {
        ClusterProvider::Eks => "arn:aws:eks:us-east-1:111122223333:cluster/synthetic-cluster",
        _ => {
            "/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/synthetic/providers/Microsoft.ContainerService/managedClusters/synthetic-cluster"
        }
    };
    SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(
            ClusterIdentity::try_new(provider, id).unwrap(),
            ClusterContextBasis::Command,
            None,
        )
        .unwrap(),
    ])
    .unwrap()
}
#[test]
fn bundled_transport_tables_are_disjoint_and_pass_the_shared_mapping_contract() {
    for (bytes, provider, id) in [
        (EKS, ClusterProvider::Eks, "mapping-eks-audit"),
        (AKS, ClusterProvider::Aks, "mapping-aks-audit"),
    ] {
        let context = context(provider);
        let mapper = KubernetesMapping::all()
            .unwrap()
            .into_iter()
            .find(|m| Module::manifest(m).id == id)
            .unwrap();
        irmind_testkit::run_cluster_source_mapping_contract(
            Arc::new(irmind_mod_parser_kubernetes::KubernetesSourceDecoder),
            Arc::new(mapper),
            "export.json",
            bytes,
            2,
            Some(&context),
        )
        .unwrap();
    }
}
#[test]
fn transport_tables_use_audit_status_and_keep_request_bodies_out_of_search() {
    for (bytes, provider, id) in [
        (EKS, ClusterProvider::Eks, "mapping-eks-audit"),
        (AKS, ClusterProvider::Aks, "mapping-aks-audit"),
    ] {
        let reference = SourceReferenceV1::file("export.json").unwrap();
        let context = context(provider);
        let cancel = CancellationToken::new();
        let mapper = KubernetesMapping::all()
            .unwrap()
            .into_iter()
            .find(|m| Module::manifest(m).id == id)
            .unwrap();
        let mut results = Vec::new();
        irmind_mod_parser_kubernetes::KubernetesSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &reference,
                        evidence_hash: irmind_app::sha256(bytes),
                        time_context: None,
                        cluster_context: Some(&context),
                        cancel: &cancel,
                    },
                    reader: &mut std::io::Cursor::new(bytes),
                },
                &mut |row| {
                    row.inspect(|source| results.push(mapper.map(source).unwrap()));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            results[0].record().common.event().outcome(),
            EventOutcome::Failure
        );
        assert_eq!(
            results[1].record().common.event().outcome(),
            EventOutcome::Success
        );
        for (index, result) in results.into_iter().enumerate() {
            assert!(
                !result
                    .record()
                    .indexed
                    .record
                    .text
                    .contains("never-project-this-body")
            );
            if index == 0 {
                assert!(
                    matches!(result.record().common.context().get(CommonField::OrchestratorNamespace), Some(CommonValue::Text(value)) if value.as_str() == "production")
                );
            } else {
                assert!(
                    result
                        .record()
                        .common
                        .context()
                        .get(CommonField::OrchestratorNamespace)
                        .is_none()
                );
            }
            assert!(
                result
                    .record()
                    .common
                    .observations()
                    .values()
                    .iter()
                    .any(|o| o.role() == irmind_domain::EntityRole::Actor)
            );
        }
    }
}
