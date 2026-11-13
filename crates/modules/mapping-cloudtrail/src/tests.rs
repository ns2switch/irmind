use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{MappingCatalog, SourceInput, SourceMetadata},
};
use irmind_domain::{CommonField, EntityRole, EventCategory, EventOutcome, SourceReferenceV1};
use serde_json::{Value, json};
const FIXTURE: &[u8] =
    include_bytes!("../../../testkit/fixtures/common/cloudtrail-console-login.jsonl");
fn decode(value: &Value) -> SourceRecordV1 {
    let bytes = serde_json::to_vec(value).unwrap();
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let report = irmind_mod_parser_json::JsonSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &SourceReferenceV1::file("cloudtrail.json").unwrap(),
                    evidence_hash: irmind_app::sha256(&bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |record| {
                record.inspect(|r| records.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
    records.remove(0)
}
fn fixture() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}
#[test]
fn included_definition_has_a_fixed_digest_and_passes_the_shared_contract() {
    let mapper = CloudTrailMapping::new().unwrap();
    assert_eq!(
        SourceMapper::manifest(&mapper)
            .identity()
            .implementation()
            .as_str(),
        DIGEST
    );
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_json::JsonSourceDecoder),
        Arc::new(mapper),
        "cloudtrail.json",
        FIXTURE,
        1,
    )
    .unwrap();
}
#[test]
fn console_login_uses_documented_result_values_and_never_infers_missing_success() {
    let mapper = CloudTrailMapping::new().unwrap();
    for (status, expected) in [
        (Some("Success"), EventOutcome::Success),
        (Some("Failure"), EventOutcome::Failure),
        (None, EventOutcome::Unknown),
    ] {
        let mut value = fixture();
        value["responseElements"] = status.map_or(Value::Null, |s| json!({"ConsoleLogin":s}));
        let source = decode(&value);
        let output = mapper.map(&source).unwrap();
        assert!(
            output
                .record()
                .common
                .event()
                .categories()
                .contains(EventCategory::Authentication)
        );
        assert_eq!(output.record().common.event().outcome(), expected);
        assert_eq!(output.record().common.origin(), source.origin());
        assert_eq!(output.record().common.timestamp(), source.timestamp());
    }
}
#[test]
fn exact_operations_and_api_form_control_outcome_without_action_name_guessing() {
    let mapper = CloudTrailMapping::new().unwrap();
    for (event_type, error, expected) in [
        (Some("AwsApiCall"), None, EventOutcome::Success),
        (
            Some("AwsApiCall"),
            Some("AccessDenied"),
            EventOutcome::Failure,
        ),
        (None, None, EventOutcome::Unknown),
    ] {
        let mut value = fixture();
        value["eventSource"] = json!("sts.amazonaws.com");
        value["eventName"] = json!("AssumeRole");
        value.as_object_mut().unwrap().remove("eventType");
        if let Some(t) = event_type {
            value["eventType"] = json!(t);
        }
        if let Some(e) = error {
            value["errorCode"] = json!(e);
        }
        assert_eq!(
            mapper
                .map(&decode(&value))
                .unwrap()
                .record()
                .common
                .event()
                .outcome(),
            expected
        );
    }
    let mut value = fixture();
    value["eventName"] = json!("LooksLikeAdminAuthenticationSuccess");
    let output = mapper.map(&decode(&value)).unwrap();
    assert_eq!(output.record().common.event().categories().bits(), 0);
    assert_eq!(
        output.record().common.event().outcome(),
        EventOutcome::Unknown
    );
}
#[test]
fn actor_target_and_account_namespaces_are_preserved_without_process_inference() {
    let mapper = CloudTrailMapping::new().unwrap();
    let mut value = fixture();
    value["requestParameters"] = json!({"userName":"alice","pid":42});
    let first = mapper.map(&decode(&value)).unwrap();
    let obs = first.record().common.observations().values();
    let actor = obs
        .iter()
        .find(|o| o.field() == CommonField::UserName)
        .unwrap();
    let target = obs
        .iter()
        .find(|o| o.field() == CommonField::UserTargetName)
        .unwrap();
    assert_eq!(actor.entity(), target.entity());
    assert_eq!(
        (actor.role(), target.role()),
        (EntityRole::Actor, EntityRole::Target)
    );
    value["requestParameters"]["userName"] = json!("bob");
    let distinct = mapper.map(&decode(&value)).unwrap();
    assert!(
        distinct
            .record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.role() == EntityRole::Target && o.entity().value() == "bob")
    );
    value["recipientAccountId"] = json!("444455556666");
    value["userIdentity"]["accountId"] = json!("444455556666");
    let other = mapper.map(&decode(&value)).unwrap();
    let other_actor = other
        .record()
        .common
        .observations()
        .values()
        .iter()
        .find(|o| o.field() == CommonField::UserName)
        .unwrap();
    assert_ne!(actor.entity(), other_actor.entity());
    assert!(
        !other
            .record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.entity().kind() == irmind_domain::ObservedEntityKind::Process)
    );
}
#[test]
fn generic_and_cloudtrail_selectors_are_disjoint_and_overlap_is_still_an_error() {
    let catalog = MappingCatalog::freeze(
        vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
        vec![
            Arc::new(CloudTrailMapping::new().unwrap()),
            Arc::new(
                irmind_mod_mapping_json_compat::JsonCompatibilityMapping::generic_only().unwrap(),
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        catalog.map(&decode(&fixture())).unwrap().0.unwrap().id(),
        "mapping-cloudtrail"
    );
    let mut generic = fixture();
    generic.as_object_mut().unwrap().remove("eventVersion");
    assert_eq!(
        catalog.map(&decode(&generic)).unwrap().0.unwrap().id(),
        "mapping-json-compat"
    );
    assert!(
        MappingCatalog::freeze(
            vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
            vec![
                Arc::new(CloudTrailMapping::new().unwrap()),
                Arc::new(irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap())
            ],
        )
        .is_err()
    );
}
