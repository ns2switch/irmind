use super::*;
#[test]
fn bundled_definitions_have_pinned_identities() {
    let host = TableMapping::review(include_str!("host.toml")).unwrap();
    let kube = TableMapping::review(include_str!("kubernetes.toml")).unwrap();
    assert_eq!(
        host.identity().implementation().as_str(),
        "000c426da8641a51750f3a7ebc18e2881d1d3c56c4062e6b9c9deddc62d5ed31"
    );
    assert_eq!(
        kube.identity().implementation().as_str(),
        "cc16f78e9c2ffe4ebf767ef58296d66a7d88ab27ec4472781a38aeb74b0701b7"
    );
    HostMapping::new().unwrap();
    KubernetesMapping::new().unwrap();
}

use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{EntityIdentityScope, EventCategory, EventKind, ObservedEntityKind};
const FIXTURE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-falco/source/event.ndjson");
fn context() -> irmind_domain::SourceClusterContext {
    irmind_app::command_cluster_context(Some("kubernetes:urn:k8s:synthetic"))
        .unwrap()
        .unwrap()
}
fn decode(bytes: &[u8], cluster: bool) -> SourceRecordV1 {
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let binding = context();
    let mut rows = Vec::new();
    let report = irmind_mod_parser_falco::FalcoSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: cluster.then_some(&binding),
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |r| {
                r.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    rows.remove(0)
}
#[test]
fn source_alert_keeps_container_and_pod_cluster_scope_without_creating_a_confirmed_finding() {
    let source = decode(FIXTURE, true);
    let output = KubernetesMapping::new().unwrap().map(&source).unwrap();
    let common = &output.record().common;
    assert_eq!(common.event().kind(), EventKind::Alert);
    assert!(
        common
            .event()
            .categories()
            .contains(EventCategory::IntrusionDetection)
    );
    assert!(source.fields().field("confirmed").is_none());
    for kind in [
        ObservedEntityKind::Container,
        ObservedEntityKind::KubernetesNamespace,
        ObservedEntityKind::KubernetesPod,
    ] {
        assert!(
            common
                .observations()
                .values()
                .iter()
                .any(|o| o.entity().kind() == kind
                    && matches!(o.entity().scope(), EntityIdentityScope::Cluster { .. }))
        );
    }
    assert!(
        common
            .observations()
            .values()
            .iter()
            .filter(|o| o.entity().kind() == ObservedEntityKind::Process)
            .all(|o| matches!(o.entity().scope(), EntityIdentityScope::SourceRecord { .. }))
    );
}
#[test]
fn container_os_user_is_not_a_kubernetes_api_principal_and_pid_reuse_is_not_a_lifetime() {
    let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    value["output_fields"]["user.name"] = serde_json::json!("root");
    value["output_fields"]["container.image.repository"] =
        serde_json::json!("registry.example.test/synthetic");
    let bytes = serde_json::to_vec(&value).unwrap();
    let source = decode(&bytes, true);
    let output = KubernetesMapping::new().unwrap().map(&source).unwrap();
    let users = output.record().common.observations().values();
    assert!(
        users
            .iter()
            .any(|o| o.entity().kind() == ObservedEntityKind::User
                && o.entity().value() == "root"
                && matches!(o.entity().scope(), EntityIdentityScope::SourceRecord { .. }))
    );
    assert!(
        !users
            .iter()
            .any(|o| o.entity().kind() == ObservedEntityKind::KubernetesUser
                || matches!(
                    o.entity().scope(),
                    EntityIdentityScope::ProcessLifetime { .. }
                ))
    );
}
#[test]
fn host_and_kubernetes_selectors_are_disjoint_and_share_the_mapping_contract() {
    use std::sync::Arc;
    let host = HostMapping::new().unwrap();
    let kube = KubernetesMapping::new().unwrap();
    assert!(
        SourceMapper::manifest(&host).selectors()[0]
            .overlap_witness(&SourceMapper::manifest(&kube).selectors()[0])
            .is_none()
    );
    irmind_testkit::run_cluster_source_mapping_contract(
        Arc::new(irmind_mod_parser_falco::FalcoSourceDecoder),
        Arc::new(kube),
        "synthetic.ndjson",
        FIXTURE,
        1,
        Some(&context()),
    )
    .unwrap();
    let source = decode(FIXTURE, true);
    assert!(host.map(&source).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    value["output_fields"] = serde_json::json!({"proc.name":"sh", "proc.pid":42});
    let bytes = serde_json::to_vec(&value).unwrap();
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_falco::FalcoSourceDecoder),
        Arc::new(host),
        "synthetic.ndjson",
        &bytes,
        1,
    )
    .unwrap();
}
#[test]
fn audit_plugin_roles_scope_and_explicit_response_code_pass_shared_contract() {
    let fixture = include_bytes!("../../../testkit/fixtures/parser-falco/source/audit.ndjson");
    let mapper = AuditPluginMapping::new().unwrap();
    let source = decode(fixture, true);
    let projection = mapper.map(&source).unwrap();
    let common = &projection.record().common;
    assert_eq!(common.event().kind(), EventKind::Alert);
    assert_eq!(
        common.event().outcome(),
        irmind_domain::EventOutcome::Unknown
    );
    assert!(common.event().categories().contains(EventCategory::Api));
    assert!(matches!(
        common
            .context()
            .get(irmind_domain::CommonField::HttpResponseStatusCode),
        Some(irmind_domain::CommonValue::Unsigned(403))
    ));
    for (kind, role, value) in [
        (
            ObservedEntityKind::KubernetesUser,
            irmind_domain::EntityRole::Actor,
            "system:serviceaccount:operations:reader",
        ),
        (
            ObservedEntityKind::KubernetesUser,
            irmind_domain::EntityRole::Target,
            "synthetic-target",
        ),
        (
            ObservedEntityKind::Ip,
            irmind_domain::EntityRole::Source,
            "203.0.113.77",
        ),
    ] {
        assert!(
            common
                .observations()
                .values()
                .iter()
                .any(|o| o.entity().kind() == kind
                    && o.role() == role
                    && o.entity().value() == value)
        );
    }
    irmind_testkit::run_cluster_source_mapping_contract(
        Arc::new(irmind_mod_parser_falco::FalcoSourceDecoder),
        Arc::new(mapper),
        "audit.ndjson",
        fixture,
        1,
        Some(&context()),
    )
    .unwrap();
}
#[test]
fn explicit_container_privilege_is_a_boolean_and_never_a_process_lifetime() {
    let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    value["output_fields"]["container.privileged"] = serde_json::json!(true);
    let source = decode(&serde_json::to_vec(&value).unwrap(), true);
    let mapped = KubernetesMapping::new().unwrap().map(&source).unwrap();
    assert_eq!(
        mapped
            .record()
            .common
            .context()
            .get(irmind_domain::CommonField::ContainerSecurityContextPrivileged),
        Some(&irmind_domain::CommonValue::Boolean(true))
    );
    assert!(
        mapped
            .record()
            .common
            .observations()
            .values()
            .iter()
            .all(|o| !matches!(
                o.entity().scope(),
                EntityIdentityScope::ProcessLifetime { .. }
            ))
    );
}
