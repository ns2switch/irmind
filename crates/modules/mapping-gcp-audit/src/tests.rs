use super::*;
#[test]
fn bundled_tables_pin_their_definitions() {
    let cloud = TableMapping::review(CLOUD).unwrap();
    let gke = TableMapping::review(include_str!("gke.toml")).unwrap();
    assert_eq!(
        (
            cloud.identity().implementation().as_str(),
            gke.identity().implementation().as_str()
        ),
        (
            CLOUD_DIGEST,
            "0114a289c7b4a50c8c37dd2f3f721f38166506874add399cbb415fb03defcbcf"
        )
    );
}

use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{
    CommonField as F, EntityIdentityScope, EntityRole, EventCategory, EventOutcome,
    ObservedEntityKind,
};
use serde_json::{Value, json};
const SOURCE: &[u8] =
    include_bytes!("../../../testkit/fixtures/parser-gcp-audit/source/event.ndjson");
const GKE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-gcp-audit/source/gke.ndjson");
fn decode(value: &Value, gke: bool) -> SourceRecordV1 {
    let bytes = serde_json::to_vec(value).unwrap();
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let context = gke.then(|| {
        let identity = format!(
            "gke:projects/{}/locations/{}/clusters/{}",
            value["resource"]["labels"]["project_id"].as_str().unwrap(),
            value["resource"]["labels"]["location"].as_str().unwrap(),
            value["resource"]["labels"]["cluster_name"]
                .as_str()
                .unwrap()
        );
        irmind_app::command_cluster_context(Some(&identity))
            .unwrap()
            .unwrap()
    });
    let report = irmind_mod_parser_gcp_audit::GcpAuditSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(&bytes),
                    time_context: None,
                    cluster_context: context.as_ref(),
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(&bytes),
            },
            &mut |r| {
                r.inspect(|r| records.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    records.remove(0)
}
#[test]
fn admin_and_data_access_keep_actor_resource_roles_and_explicit_outcomes() {
    let interpreter = CloudAuditMapping::new().unwrap();
    for (code, outcome) in [
        (Some(0), EventOutcome::Success),
        (Some(7), EventOutcome::Failure),
        (None, EventOutcome::Unknown),
    ] {
        let mut value: Value = serde_json::from_slice(SOURCE).unwrap();
        if let Some(code) = code {
            value["protoPayload"]["status"] = json!({"code":code});
        } else {
            value["protoPayload"]
                .as_object_mut()
                .unwrap()
                .remove("status");
        }
        value["logName"] =
            json!("projects/synthetic-project/logs/cloudaudit.googleapis.com%2Fdata_access");
        let source = decode(&value, false);
        let output = interpreter.map(&source).unwrap();
        let common = &output.record().common;
        assert!(common.event().categories().contains(EventCategory::Iam));
        assert_eq!(common.event().outcome(), outcome);
        assert_eq!(common.origin(), source.origin());
        assert!(
            common
                .observations()
                .values()
                .iter()
                .any(|o| o.entity().value() == "analyst@example.invalid"
                    && o.role() == EntityRole::Actor)
        );
        assert!(
            common
                .observations()
                .values()
                .iter()
                .any(|o| o.entity().kind() == ObservedEntityKind::Resource
                    && o.role() == EntityRole::Target)
        );
        assert!(!common.observations().values().iter().any(|o| matches!(
            o.entity().scope(),
            EntityIdentityScope::ProcessLifetime { .. }
        )));
    }
}
#[test]
fn same_address_has_two_roles_but_provider_redaction_is_not_an_ip() {
    let mut value: Value = serde_json::from_slice(SOURCE).unwrap();
    value["protoPayload"]["requestMetadata"]["destinationAttributes"] =
        json!({"ip":"203.0.113.77","port":"443"});
    let interpreter = CloudAuditMapping::new().unwrap();
    let output = interpreter.map(&decode(&value, false)).unwrap();
    let values = output.record().common.observations().values();
    let source = values.iter().find(|o| o.field() == F::SourceIp).unwrap();
    let dest = values
        .iter()
        .find(|o| o.field() == F::DestinationIp)
        .unwrap();
    assert_eq!(source.entity(), dest.entity());
    assert_ne!(source.role(), dest.role());
    for redacted in ["private", "gce-internal-ip"] {
        value["protoPayload"]["requestMetadata"]["callerIp"] = json!(redacted);
        let output = interpreter.map(&decode(&value, false)).unwrap();
        assert!(output.record().common.context().get(F::SourceIp).is_none());
    }
}
#[test]
fn gke_typed_pod_namespace_and_actor_use_confirmed_identity_and_safe_projection() {
    let mut value: Value = serde_json::from_slice(GKE).unwrap();
    value["protoPayload"]["resourceName"] = json!("core/v1/namespaces/production/pods/frontend");
    let source = decode(&value, true);
    let output = GkeMapping::new().unwrap().map(&source).unwrap();
    assert_eq!(
        output.record().common.event().outcome(),
        EventOutcome::Failure
    );
    let pod = output
        .record()
        .common
        .observations()
        .values()
        .iter()
        .find(|o| o.entity().kind() == ObservedEntityKind::KubernetesPod)
        .unwrap();
    assert_eq!(pod.entity().value(), "frontend");
    assert_eq!(pod.role(), EntityRole::Target);
    assert!(
        matches!(pod.entity().scope(),EntityIdentityScope::Cluster{namespace:Some(ns),..} if ns.as_str()=="production")
    );
    assert!(
        !output
            .record()
            .indexed
            .record
            .text
            .contains("never-project-this-body")
    );
    assert!(
        source
            .fields()
            .field("protoPayload")
            .unwrap()
            .field("request")
            .is_some()
    );
}
#[test]
fn policy_changes_are_iam_by_exact_method_and_unknown_services_remain_unclassified() {
    let interpreter = CloudAuditMapping::new().unwrap();
    let mut value: Value = serde_json::from_slice(SOURCE).unwrap();
    value["protoPayload"]["serviceName"] = json!("cloudresourcemanager.googleapis.com");
    value["protoPayload"]["methodName"] = json!("SetIamPolicy");
    assert!(
        interpreter
            .map(&decode(&value, false))
            .unwrap()
            .record()
            .common
            .event()
            .categories()
            .contains(EventCategory::Iam)
    );
    value["protoPayload"]["methodName"] = json!("future_unmapped_operation");
    assert_eq!(
        interpreter
            .map(&decode(&value, false))
            .unwrap()
            .record()
            .common
            .event()
            .categories()
            .bits(),
        0
    );
}

#[test]
fn gke_zonal_location_is_not_silently_renamed_to_a_region() {
    let mut value: Value = serde_json::from_slice(GKE).unwrap();
    let interpreter = GkeMapping::new().unwrap();
    let regional = interpreter.map(&decode(&value, true)).unwrap();
    assert!(
        regional
            .record()
            .common
            .context()
            .get(F::CloudRegion)
            .is_some()
    );
    value["resource"]["labels"]["location"] = json!("us-central1-a");
    let zonal = interpreter.map(&decode(&value, true)).unwrap();
    assert!(
        zonal
            .record()
            .common
            .context()
            .get(F::CloudRegion)
            .is_none()
    );
}

#[test]
fn native_cloud_and_gke_pass_the_same_pure_mapping_and_custody_contract() {
    use std::sync::Arc;
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_gcp_audit::GcpAuditSourceDecoder),
        Arc::new(CloudAuditMapping::new().unwrap()),
        "synthetic.ndjson",
        SOURCE,
        1,
    )
    .unwrap();
    let context = irmind_app::command_cluster_context(Some(
        "gke:projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
    ))
    .unwrap()
    .unwrap();
    irmind_testkit::run_cluster_source_mapping_contract(
        Arc::new(irmind_mod_parser_gcp_audit::GcpAuditSourceDecoder),
        Arc::new(GkeMapping::new().unwrap()),
        "synthetic.ndjson",
        GKE,
        1,
        Some(&context),
    )
    .unwrap();
}

#[test]
fn another_service_cannot_turn_a_project_principal_into_a_kubernetes_user() {
    let mut value: Value = serde_json::from_slice(GKE).unwrap();
    value["protoPayload"]["serviceName"] = json!("unknown.googleapis.com");
    let source = decode(&value, true);
    let interpreter = GkeMapping::new().unwrap();
    assert!(
        !SourceMapper::manifest(&interpreter)
            .selectors()
            .iter()
            .any(|s| s.matches(&source))
    );
    assert!(interpreter.map(&source).is_err());
}
