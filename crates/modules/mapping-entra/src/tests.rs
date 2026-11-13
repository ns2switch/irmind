use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{
    CommonField as F, EntityRole as R, EventCategory, EventOutcome, ObservedEntityKind as K,
};
use serde_json::{Value, json};
const SIGNIN: &str =
    include_str!("../../../testkit/fixtures/parser-entra/source/signin-resource.ndjson");
const SIGNIN_TABLE: &str =
    include_str!("../../../testkit/fixtures/parser-entra/source/signin-table.ndjson");
const AUDIT: &str =
    include_str!("../../../testkit/fixtures/parser-entra/source/audit-resource.ndjson");
const AUDIT_TABLE: &str =
    include_str!("../../../testkit/fixtures/parser-entra/source/audit-table.ndjson");
fn decode(value: &Value) -> SourceRecordV1 {
    let bytes = serde_json::to_vec(value).unwrap();
    let source = SourceReferenceV1::file("synthetic.json").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::new();
    let report = irmind_mod_parser_entra::EntraSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(&bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(&bytes),
            },
            &mut |row| {
                row.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    rows.remove(0)
}
fn map(value: &Value) -> MappingOutput {
    let source = decode(value);
    let mapper = EntraMapping::all()
        .unwrap()
        .into_iter()
        .find(|m| m.format == source.format().id())
        .unwrap();
    mapper.map(&source).unwrap()
}
#[test]
fn all_included_definitions_pass_shared_contracts_and_have_disjoint_source_formats() {
    for (fixture, format) in [
        (SIGNIN, "entra-signin-resource"),
        (SIGNIN_TABLE, "entra-signin-table"),
        (AUDIT, "entra-audit-resource"),
        (AUDIT_TABLE, "entra-audit-table"),
    ] {
        let mapper = EntraMapping::all()
            .unwrap()
            .into_iter()
            .find(|m| m.format == format)
            .unwrap();
        irmind_testkit::run_source_mapping_contract(
            Arc::new(irmind_mod_parser_entra::EntraSourceDecoder),
            Arc::new(mapper),
            "synthetic.json",
            fixture.as_bytes(),
            1,
        )
        .unwrap();
    }
}
#[test]
fn signin_success_failure_missing_and_conditional_access_remain_distinct() {
    for (fixture, table) in [(SIGNIN, false), (SIGNIN_TABLE, true)] {
        for (code, outcome) in [
            (Some(0), EventOutcome::Success),
            (Some(50076), EventOutcome::Failure),
            (None, EventOutcome::Unknown),
        ] {
            let mut value: Value = serde_json::from_str(fixture).unwrap();
            if table {
                if let Some(code) = code {
                    value["ResultType"] = json!(code.to_string());
                } else {
                    value.as_object_mut().unwrap().remove("ResultType");
                }
                value["ConditionalAccessStatus"] = json!("failure");
            } else if let Some(code) = code {
                value["resultType"] = json!(code.to_string());
                value["properties"]["status"]["errorCode"] = json!(code);
            } else {
                value.as_object_mut().unwrap().remove("resultType");
                value["properties"]
                    .as_object_mut()
                    .unwrap()
                    .remove("status");
            }
            let out = map(&value);
            assert_eq!(out.record().common.event().outcome(), outcome);
            assert!(
                out.record()
                    .common
                    .event()
                    .categories()
                    .contains(EventCategory::Authentication)
            );
            assert!(
                out.record()
                    .common
                    .observations()
                    .values()
                    .iter()
                    .any(|o| o.role() == R::Actor)
            );
            assert!(
                out.record()
                    .common
                    .observations()
                    .values()
                    .iter()
                    .any(|o| o.role() == R::Source && o.entity().kind() == K::Ip)
            );
            assert!(
                out.record()
                    .indexed
                    .record
                    .text
                    .contains("multiFactorAuthentication")
            );
        }
    }
}
#[test]
fn audit_actor_target_and_same_user_in_two_roles_keep_their_occurrences() {
    let mut value: Value = serde_json::from_str(AUDIT).unwrap();
    value["properties"]["targetResources"] = json!([{"type":"User","id":"synthetic-user-1","userPrincipalName":"analyst@example.invalid"}]);
    let out = map(&value);
    let observations = out.record().common.observations().values();
    let actor = observations
        .iter()
        .find(|o| o.field() == F::UserName)
        .unwrap();
    let target = observations
        .iter()
        .find(|o| o.field() == F::UserTargetName)
        .unwrap();
    assert_eq!(actor.entity(), target.entity());
    assert_eq!((actor.role(), target.role()), (R::Actor, R::Target));
    value["properties"]["targetResources"][0]["id"] = json!("synthetic-target-2");
    value["properties"]["targetResources"][0]["userPrincipalName"] =
        json!("target@example.invalid");
    let out = map(&value);
    let observations = out.record().common.observations().values();
    assert!(
        observations
            .iter()
            .any(|o| o.entity().value() == "target@example.invalid" && o.role() == R::Target)
    );
    assert!(
        observations
            .iter()
            .any(|o| o.entity().value() == "analyst@example.invalid" && o.role() == R::Actor)
    );
}
#[test]
fn tenant_scope_uses_aad_tenant_and_never_the_log_analytics_workspace() {
    let mut value: Value = serde_json::from_str(SIGNIN_TABLE).unwrap();
    value["TenantId"] = json!("workspace-id-must-not-be-an-identity-tenant");
    let a = map(&value);
    value["AADTenantId"] = json!("00000000-0000-4000-8000-000000000002");
    let b = map(&value);
    let actor = |v: &MappingOutput| {
        v.record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == F::UserId)
            .unwrap()
            .entity()
            .clone()
    };
    assert_ne!(actor(&a), actor(&b));
    assert!(
        !a.record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.entity().value() == "workspace-id-must-not-be-an-identity-tenant")
    );
}
#[test]
fn table_dynamic_fields_can_be_encoded_json_without_rewriting_original_types() {
    let mut value: Value = serde_json::from_str(AUDIT_TABLE).unwrap();
    value["InitiatedBy"] = json!(serde_json::to_string(&value["InitiatedBy"]).unwrap());
    value["TargetResources"] = json!(serde_json::to_string(&value["TargetResources"]).unwrap());
    let out = map(&value);
    assert!(
        out.record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.role() == R::Actor)
    );
    assert!(
        out.record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.role() == R::Target)
    );
    assert!(matches!(
        decode(&value).fields().field("TargetResources"),
        Some(irmind_app::source_mapping::SourceValue::Text(_))
    ));
}
#[test]
fn service_principal_and_noninteractive_records_do_not_infer_a_process_lifetime() {
    let mut value: Value = serde_json::from_str(SIGNIN_TABLE).unwrap();
    for kind in [
        "AADNonInteractiveUserSignInLogs",
        "AADServicePrincipalSignInLogs",
    ] {
        value["Type"] = json!(kind);
        value["ProcessGuid"] = json!("untrusted-extra");
        value["pid"] = json!(123);
        if kind == "AADServicePrincipalSignInLogs" {
            value["UserId"] = Value::Null;
            value["UserPrincipalName"] = Value::Null;
            value["ServicePrincipalId"] = json!("synthetic-service-principal");
            value["ServicePrincipalName"] = json!("Synthetic application");
            value["ResultType"] = json!("Success");
        }
        let out = map(&value);
        assert!(
            out.record()
                .common
                .observations()
                .values()
                .iter()
                .any(|o| o.role() == R::Actor)
        );
        assert!(
            !out.record()
                .common
                .observations()
                .values()
                .iter()
                .any(|o| o.entity().kind() == K::Process)
        );
    }
}
#[test]
fn contradictory_reported_status_is_unknown_with_a_visible_coverage_diagnostic() {
    let mut value: Value = serde_json::from_str(SIGNIN).unwrap();
    value["properties"]["status"]["errorCode"] = json!(0);
    let out = map(&value);
    assert_eq!(out.record().common.event().outcome(), EventOutcome::Unknown);
    assert!(
        out.diagnostics()
            .contains(&irmind_app::source_mapping::MappingDiagnostic::UnsupportedValue)
    );
}

#[test]
fn encoded_dynamic_values_are_single_bounded_json_values() {
    let mut value: Value = serde_json::from_str(AUDIT_TABLE).unwrap();
    value["InitiatedBy"] = json!("{\"user\":{\"id\":\"synthetic-actor\"}},\"extra\":{}");
    let source = decode(&value);
    let mapper = EntraMapping::all()
        .unwrap()
        .into_iter()
        .find(|m| m.format == "entra-audit-table")
        .unwrap();
    assert!(mapper.map(&source).is_err());
    value["InitiatedBy"] = json!(" ".repeat(65537));
    assert!(mapper.map(&decode(&value)).is_err());
}
