#![allow(clippy::unwrap_used)]
use super::*;
use irmind_domain::*;
const TENANT: &str = "00000000000000000000000000000001";
const HOST: &str = "00000000000000000000000000000100";
fn event(
    parser: &str,
    version: &str,
    host: Option<&str>,
    tenant: &str,
    id: &str,
) -> Result<CommonEventV1, EventSchemaError> {
    let scope = EntityIdentityScope::provider_process(
        ProcessIdentityProvider::CrowdStrikeFdr,
        tenant,
        HOST,
    )?;
    let entity = ObservedEntity::try_new(ObservedEntityKind::Process, id, scope)?;
    let observation =
        EntityObservation::try_new(entity, EntityRole::Subject, CommonField::ProcessEntityId)?;
    let mut context = EventContextV1::default();
    context.try_insert(
        CommonField::ProcessEntityId,
        CommonValue::Text(EventText::new(id)?),
    )?;
    if let Some(host) = host {
        context.try_insert(
            CommonField::HostId,
            CommonValue::Text(EventText::new(host)?),
        )?;
    }
    CommonEventV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([0xab; 32]),
            7,
            Some(42),
            parser,
            version,
        )?,
        None,
        EventHeaderV1::default(),
        context,
        BoundedObservations::try_new(vec![observation])?,
    )
}
#[test]
fn provider_process_scope_matches_approved_golden_and_round_trips() {
    let scope = EntityIdentityScope::provider_process(
        ProcessIdentityProvider::CrowdStrikeFdr,
        TENANT,
        HOST,
    )
    .unwrap();
    let encoded = encode_identity_scope(&scope).unwrap();
    assert_eq!(
        encoded.as_bytes(),
        include_bytes!("../../../../docs/development/fdr-process-vectors/scope.json")
    );
    assert_eq!(decode_identity_scope(&encoded).unwrap(), scope);
    let expected = include_str!("../../../../docs/development/fdr-process-vectors/scope.sha256")
        .split_ascii_whitespace()
        .next()
        .unwrap();
    assert_eq!(crate::hex(&crate::sha256(encoded.as_bytes())), expected);
    let event = event(
        "parser-fdr",
        "fdr-source-v1",
        Some(HOST),
        TENANT,
        "18446744073709551615",
    )
    .unwrap();
    let json = encode_common_event(&event).unwrap();
    assert_eq!(
        json.as_bytes(),
        include_bytes!("../../../../docs/development/fdr-process-vectors/event.json")
    );
    assert_eq!(decode_common_event(&json).unwrap(), event);
    for altered in [
        json.replace("crowdstrike-fdr", "other-provider"),
        json.replace("provider_process", "unknown_scope"),
        json.replace("18446744073709551615", "18446744073709551616"),
        json.replace("fdr-source-v1", "fdr-source-v2"),
    ] {
        assert!(decode_common_event(&altered).is_err());
    }
}
#[test]
fn provider_process_origin_and_host_context_are_mandatory() {
    assert!(event("parser-json", "json-source-v1", Some(HOST), TENANT, "42").is_err());
    assert!(event("parser-fdr", "fdr-source-v2", Some(HOST), TENANT, "42").is_err());
    assert!(event("parser-fdr", "fdr-source-v1", None, TENANT, "42").is_err());
    assert!(
        event(
            "parser-fdr",
            "fdr-source-v1",
            Some("00000000000000000000000000000101"),
            TENANT,
            "42"
        )
        .is_err()
    );
}
