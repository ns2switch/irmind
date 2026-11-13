use super::*;
use crate::{ClusterIdentity, ClusterProvider};
fn cluster(name: &str) -> ClusterIdentity {
    ClusterIdentity::try_new(ClusterProvider::Kubernetes, &format!("urn:k8s:{name}")).unwrap()
}
fn pod(cluster_name: &str, namespace: &str) -> ObservedEntity {
    ObservedEntity::try_new(
        ObservedEntityKind::KubernetesPod,
        "frontend",
        EntityIdentityScope::Cluster {
            cluster: cluster(cluster_name),
            namespace: Some(EventText::identifier(namespace).unwrap()),
        },
    )
    .unwrap()
}
#[test]
fn cluster_and_namespace_are_both_part_of_entity_identity() {
    let a = pod("a", "production");
    for b in [pod("b", "production"), pod("a", "test")] {
        assert_ne!(a, b);
        assert_ne!(a.stable_cmp(&b), std::cmp::Ordering::Equal);
    }
    assert!(
        ObservedEntity::try_new(
            ObservedEntityKind::KubernetesPod,
            "frontend",
            EntityIdentityScope::Global
        )
        .is_err()
    );
    assert!(
        ObservedEntity::try_new(
            ObservedEntityKind::KubernetesPod,
            "frontend",
            EntityIdentityScope::Cluster {
                cluster: cluster("a"),
                namespace: None
            }
        )
        .is_err()
    );
    for bad in ["../production", "UpperCase", "x\n", "", "-production"] {
        let result = EventText::identifier(bad).and_then(|namespace| {
            ObservedEntity::try_new(
                ObservedEntityKind::KubernetesPod,
                "frontend",
                EntityIdentityScope::Cluster {
                    cluster: cluster("a"),
                    namespace: Some(namespace),
                },
            )
        });
        assert!(result.is_err(), "{bad:?}");
    }
}
#[test]
fn cluster_observations_cannot_claim_another_acquisition_identity() {
    let mut context = EventContextV1::default();
    context
        .try_insert(
            CommonField::IrmindClusterIdentity,
            CommonValue::Text(EventText::new(&cluster("b").qualified()).unwrap()),
        )
        .unwrap();
    context
        .try_insert(
            CommonField::IrmindKubernetesPod,
            CommonValue::Text(EventText::identifier("frontend").unwrap()),
        )
        .unwrap();
    context
        .try_insert(
            CommonField::OrchestratorNamespace,
            CommonValue::Text(EventText::identifier("production").unwrap()),
        )
        .unwrap();
    let observations = BoundedObservations::try_new(vec![
        EntityObservation::try_new(
            pod("a", "production"),
            EntityRole::Target,
            CommonField::IrmindKubernetesPod,
        )
        .unwrap(),
    ])
    .unwrap();
    let origin = EventOrigin::try_new(
        crate::EvidenceHash::from_bytes([7; 32]),
        0,
        Some(0),
        "parser-test",
        "source-test-v1",
    )
    .unwrap();
    assert!(
        CommonEventV1::try_new(
            origin,
            None,
            EventHeaderV1::default(),
            context,
            observations
        )
        .is_err()
    );
}
#[test]
fn raw_ecs_cluster_ids_remain_distinct_from_qualified_acquisition_metadata() {
    let mut context = EventContextV1::default();
    context
        .try_insert(
            CommonField::OrchestratorClusterId,
            CommonValue::Text(EventText::identifier("raw-exported-cluster-id").unwrap()),
        )
        .unwrap();
    assert!(
        context
            .try_insert(
                CommonField::IrmindClusterIdentity,
                CommonValue::Text(EventText::new("unqualified").unwrap())
            )
            .is_err()
    );
    context
        .try_insert(
            CommonField::IrmindClusterIdentity,
            CommonValue::Text(EventText::new(&cluster("a").qualified()).unwrap()),
        )
        .unwrap();
    context
        .try_insert(
            CommonField::ContainerSecurityContextPrivileged,
            CommonValue::Boolean(false),
        )
        .unwrap();
    assert!(
        EventContextV1::default()
            .try_insert(
                CommonField::ContainerSecurityContextPrivileged,
                CommonValue::Text(EventText::new("false").unwrap())
            )
            .is_err()
    );
}
