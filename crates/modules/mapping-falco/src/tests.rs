use super::*;
#[test]
fn bundled_definitions_have_pinned_identities() {
    let host = TableMapping::review(include_str!("host.toml")).unwrap();
    let kube = TableMapping::review(include_str!("kubernetes.toml")).unwrap();
    assert_eq!(
        host.identity().implementation().as_str(),
        "5f8cebeb48c38c7fda2703bf03a152281494624e35b201c85b7ce43f99fc37c3"
    );
    assert_eq!(
        kube.identity().implementation().as_str(),
        "69ad17a3c84d93ff9e9fcd94f7acd4b063725b1e225a07f3ca9cf4ddf64ad1fb"
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
