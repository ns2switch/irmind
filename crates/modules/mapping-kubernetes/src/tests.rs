use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{
    ClusterContextBasis, ClusterIdentity, ClusterProvider, EntityIdentityScope, EntityRole,
    EventCategory, EventOutcome, ObservedEntityKind, SourceClusterBinding, SourceClusterContext,
};
use irmind_mod_parser_kubernetes::KubernetesSourceDecoder;
use serde_json::{Value, json};
use std::io::Cursor;
const FIXTURE: &[u8] =
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
fn decode(value: &Value) -> SourceRecordV1 {
    let bytes = serde_json::to_vec(value).unwrap();
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let context = context();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = KubernetesSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(&bytes),
                    time_context: None,
                    cluster_context: Some(&context),
                    cancel: &cancel,
                },
                reader: &mut Cursor::new(&bytes),
            },
            &mut |row| {
                row.inspect(|row| rows.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    rows.remove(0)
}
fn fixture() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}
#[test]
fn bundled_definition_has_the_pinned_release_hash() {
    let manifest = TableMapping::review(DEFINITION).unwrap();
    assert_eq!(manifest.identity().implementation().as_str(), DIGEST);
    KubernetesMapping::new().unwrap();
}
#[test]
fn explicit_status_success_failure_and_absence_are_distinct() {
    let interpreter = KubernetesMapping::new().unwrap();
    for (code, outcome) in [
        (Some(201), EventOutcome::Success),
        (Some(403), EventOutcome::Failure),
        (None, EventOutcome::Unknown),
    ] {
        let mut value = fixture();
        if let Some(code) = code {
            value["responseStatus"]["code"] = json!(code);
        } else {
            value.as_object_mut().unwrap().remove("responseStatus");
        }
        let source = decode(&value);
        let mapped = interpreter.map(&source).unwrap();
        assert_eq!(mapped.record().common.event().outcome(), outcome);
        assert!(
            mapped
                .record()
                .common
                .event()
                .categories()
                .contains(EventCategory::Api)
        );
        assert_eq!(mapped.record().common.origin(), source.origin());
        assert!(
            !mapped
                .record()
                .indexed
                .record
                .text
                .contains("never-project-this-body")
        );
    }
}
#[test]
fn actor_impersonation_and_primary_source_ip_keep_their_original_roles() {
    let mut value = fixture();
    value["sourceIPs"] = json!(["203.0.113.77", "2001:db8::1"]);
    value["impersonatedUser"] = json!({"username":"bob"});
    let source = decode(&value);
    let mapped = KubernetesMapping::new().unwrap().map(&source).unwrap();
    let observations = mapped.record().common.observations().values();
    for (kind, name, role) in [
        (
            ObservedEntityKind::KubernetesUser,
            "alice",
            EntityRole::Actor,
        ),
        (
            ObservedEntityKind::KubernetesUser,
            "bob",
            EntityRole::Target,
        ),
        (ObservedEntityKind::Ip, "203.0.113.77", EntityRole::Source),
    ] {
        assert!(
            observations.iter().any(|o| o.entity().kind() == kind
                && o.entity().value() == name
                && o.role() == role)
        );
    }
    assert!(
        matches!(source.fields().field("sourceIPs"), Some(irmind_app::source_mapping::SourceValue::Array(ips)) if ips.len()==2)
    );
}
#[test]
fn same_service_account_name_in_actor_and_target_namespaces_does_not_merge() {
    let mut value = fixture();
    value["user"]["username"] = json!("system:serviceaccount:operations:builder");
    value["objectRef"]["resource"] = json!("serviceaccounts");
    value["objectRef"]["name"] = json!("builder");
    let mapped = KubernetesMapping::new()
        .unwrap()
        .map(&decode(&value))
        .unwrap();
    let accounts = mapped
        .record()
        .common
        .observations()
        .values()
        .iter()
        .filter(|o| o.entity().kind() == ObservedEntityKind::KubernetesServiceAccount)
        .collect::<Vec<_>>();
    assert_eq!(accounts.len(), 2);
    assert_ne!(accounts[0].entity(), accounts[1].entity());
    for (role, expected_namespace) in [
        (EntityRole::Actor, "operations"),
        (EntityRole::Target, "production"),
    ] {
        assert!(accounts.iter().any(|o| o.role() == role && matches!(o.entity().scope(), EntityIdentityScope::Cluster { namespace: Some(ns), .. } if ns.as_str() == expected_namespace)));
    }
}

#[test]
fn resource_type_proves_each_typed_target_and_missing_pod_namespace_is_not_inferred() {
    let interpreter = KubernetesMapping::new().unwrap();
    for (resource, name, kind, namespaced) in [
        ("pods", "frontend", ObservedEntityKind::KubernetesPod, true),
        ("nodes", "node-a", ObservedEntityKind::KubernetesNode, false),
        (
            "namespaces",
            "production",
            ObservedEntityKind::KubernetesNamespace,
            false,
        ),
        (
            "serviceaccounts",
            "builder",
            ObservedEntityKind::KubernetesServiceAccount,
            true,
        ),
    ] {
        let mut value = fixture();
        value["objectRef"]["resource"] = json!(resource);
        value["objectRef"]["name"] = json!(name);
        if !namespaced {
            value["objectRef"]
                .as_object_mut()
                .unwrap()
                .remove("namespace");
        }
        let source = decode(&value);
        let mapped = interpreter.map(&source).unwrap();
        assert!(
            mapped
                .record()
                .common
                .observations()
                .values()
                .iter()
                .any(|o| o.entity().kind() == kind
                    && o.entity().value() == name
                    && o.role() == EntityRole::Target)
        );
    }
    let mut pod = fixture();
    pod["objectRef"]["resource"] = json!("pods");
    pod["objectRef"]
        .as_object_mut()
        .unwrap()
        .remove("namespace");
    assert!(interpreter.map(&decode(&pod)).is_err());
}

#[test]
fn native_acquisition_passes_the_shared_mapping_contract() {
    irmind_testkit::run_cluster_source_mapping_contract(
        std::sync::Arc::new(KubernetesSourceDecoder),
        std::sync::Arc::new(KubernetesMapping::new().unwrap()),
        "synthetic.ndjson",
        FIXTURE,
        1,
        Some(&context()),
    )
    .unwrap();
}
