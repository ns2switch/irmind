use super::*;
use irmind_app::source_mapping::SourceValue;
use irmind_domain::{ClusterIdentity, ClusterProvider, EntityIdentityScope, ObservedEntityKind};
const DEFINITION: &str = r#"
interpreter = "irmind-mapping-tables-v2"
id = "mapping-synthetic-cluster"
version = "1"
target_schema = "irmind-common-event-v1"
source_contract = "irmind-source-record-v1"
parser = "parser-json"
parser_versions = ["json-source-v1"]
[[fields]]
source = ["ips"]
source_index = 0
target = "source.ip"
conversion = "ip"
observation = { kind = "ip", role = "source", scope = { kind = "global" } }
[[fields]]
source = ["actor"]
target = "user.name"
observation = { kind = "k8s_user", role = "actor", scope = { kind = "cluster", path = {} } }
[[fields]]
source = ["target"]
target = "user.target.name"
observation = { kind = "k8s_user", role = "target", scope = { kind = "cluster", path = {} } }
[[fields]]
source = ["principal"]
target = "irmind.kubernetes.service_account"
conversion = "kubernetes_service_account_name"
observation = { kind = "k8s_service_account", role = "actor", scope = { kind = "cluster", path = { service_account_principal = ["principal"] } } }
[[fields]]
source = ["namespace"]
target = "orchestrator.namespace"
observation = { kind = "k8s_namespace", role = "subject", scope = { kind = "cluster", path = {} } }
[[fields]]
source = ["pod"]
target = "irmind.kubernetes.pod"
observation = { kind = "k8s_pod", role = "target", scope = { kind = "cluster", path = { namespace = ["namespace"] } } }
"#;
fn source(cluster: &str, principal: &str) -> SourceRecordV1 {
    super::tests::source(
        SourceValue::object(vec![
            (
                "ips".into(),
                SourceValue::Array(vec![SourceValue::Text("203.0.113.77".into())]),
            ),
            ("actor".into(), SourceValue::Text("alice".into())),
            ("target".into(), SourceValue::Text("alice".into())),
            ("principal".into(), SourceValue::Text(principal.into())),
            ("namespace".into(), SourceValue::Text("production".into())),
            ("pod".into(), SourceValue::Text("frontend".into())),
            (
                "requestObject".into(),
                SourceValue::Text("never-project-this-body".into()),
            ),
        ])
        .unwrap(),
    )
    .with_cluster_identity(ClusterIdentity::try_new(ClusterProvider::Kubernetes, cluster).unwrap())
    .unwrap()
}
#[test]
fn cluster_scope_uses_acquisition_identity_and_principal_namespace_not_target_namespace() {
    let mapper = super::tests::mapper(DEFINITION);
    let a = mapper
        .map(&source(
            "urn:k8s:a",
            "system:serviceaccount:operations:builder",
        ))
        .unwrap();
    let b = mapper
        .map(&source(
            "urn:k8s:b",
            "system:serviceaccount:operations:builder",
        ))
        .unwrap();
    assert_ne!(a.partition().cluster(), b.partition().cluster());
    assert!(
        !a.record()
            .indexed
            .record
            .text
            .contains("never-project-this-body")
    );
    assert!(a.record().indexed.record.text.contains("203.0.113.77"));
    let observations = a.record().common.observations().values();
    let account = observations
        .iter()
        .find(|o| o.entity().kind() == ObservedEntityKind::KubernetesServiceAccount)
        .unwrap();
    assert_eq!(account.entity().value(), "builder");
    assert!(
        matches!(account.entity().scope(), EntityIdentityScope::Cluster { namespace: Some(ns), .. } if ns.as_str() == "operations")
    );
    let pod = observations
        .iter()
        .find(|o| o.entity().kind() == ObservedEntityKind::KubernetesPod)
        .unwrap();
    assert!(
        matches!(pod.entity().scope(), EntityIdentityScope::Cluster { namespace: Some(ns), .. } if ns.as_str() == "production")
    );
    let users = observations
        .iter()
        .filter(|o| o.entity().kind() == ObservedEntityKind::KubernetesUser)
        .collect::<Vec<_>>();
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].entity(), users[1].entity());
    assert_ne!(users[0].role(), users[1].role());
}
#[test]
fn ordinary_principals_omit_only_the_optional_service_account_and_malformed_ones_fail() {
    let mapper = super::tests::mapper(DEFINITION);
    let output = mapper.map(&source("urn:k8s:a", "ordinary-user")).unwrap();
    assert!(
        !output
            .record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.entity().kind() == ObservedEntityKind::KubernetesServiceAccount)
    );
    for principal in [
        "system:serviceaccount::builder",
        "system:serviceaccount:../bad:builder",
        "system:serviceaccount:operations:BadName",
    ] {
        assert!(mapper.map(&source("urn:k8s:a", principal)).is_err());
    }
}
#[test]
fn indexes_namespaces_and_acquisition_metadata_are_closed() {
    for definition in [
        DEFINITION.replace("source_index = 0", "source_index = 65535"),
        DEFINITION.replace("source_index = 0", "source_index = -1"),
        DEFINITION.replace(
            "target = \"user.name\"",
            "target = \"irmind.cluster.identity\"",
        ),
        DEFINITION.replace(
            "namespace = [\"namespace\"]",
            "namespace = [\"namespace\"], service_account_principal = [\"principal\"]",
        ),
        DEFINITION.replace("kind = \"k8s_pod\"", "kind = \"process\""),
    ] {
        assert!(TableMapping::review(&definition).is_err());
    }
}
