use super::*;
#[test]
fn namespace_is_explicit_bounded_and_not_a_path() {
    assert!(
        SiemSourceScope::instance(
            "chronicle",
            "siem-chronicle",
            "test-project",
            "europe-west2",
            "test-instance"
        )
        .is_ok()
    );
    for invalid in [
        "",
        "../foreign",
        "with/control\n",
        "project/locations/elsewhere",
    ] {
        assert!(
            SiemSourceScope::instance(
                "chronicle",
                "siem-chronicle",
                invalid,
                "europe-west2",
                "test-instance"
            )
            .is_err()
        );
    }
    let event = SiemSourceScope::event_account("elastic", "siem-elastic").unwrap();
    assert_eq!(event.mode(), SiemScopeMode::EventAccount);
    assert!(event.project().is_none());
}
fn entry(sources: Vec<SiemSourceScope>) -> SignedEntry {
    SignedEntry {
        seq: 2, case_id: "synthetic".into(), at: 1,
        actor: irmind_domain::Actor::Analyst,
        origin: AuditOrigin::System.as_str().into(), kind: AuditEventKind::ModulesActivated,
        payload: serde_json::to_string(&ScopeSnapshot {
            detail: "effective-siem-source-scopes".into(), version: 1,
            case_scope: "v1;sources=chronicle;accounts=test-project;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-02T00:00:00Z".into(),
            module_fingerprint: "synthetic".into(), policy_fingerprint: "synthetic".into(), sources,
        }).unwrap(),
        evidence: None, prev: [0;32], hash: [0;32], sig: Vec::new(), public_key: Vec::new(),
    }
}
#[test]
fn historical_instance_scope_remains_visible_after_switching_back_to_account_mode() {
    let instance = SiemSourceScope::instance(
        "chronicle",
        "siem-chronicle",
        "test-project",
        "europe-west2",
        "test-instance",
    )
    .unwrap();
    let first = entry(vec![instance.clone()]);
    let next = entry(vec![
        SiemSourceScope::event_account("chronicle", "siem-chronicle").unwrap(),
    ]);
    assert_eq!(
        recorded_instance_sources(&[first, next]).unwrap(),
        [instance]
    );
}
#[test]
fn scope_snapshot_rejects_wrong_origin_case_scope_duplicates_and_unknown_fields() {
    let scope = SiemSourceScope::event_account("chronicle", "siem-chronicle").unwrap();
    let original = entry(vec![scope.clone()]);
    let parsed: ScopeSnapshot = serde_json::from_str(&original.payload).unwrap();
    assert!(verify_entry(&original, &parsed.case_scope).is_ok());
    assert!(verify_entry(&original, "local").is_err());
    let mut forged = original.clone();
    forged.origin = AuditOrigin::Agent.as_str().into();
    assert!(verify_entry(&forged, &parsed.case_scope).is_err());
    assert!(verify_entry(&entry(vec![scope.clone(), scope]), &parsed.case_scope).is_err());
    let mut body: serde_json::Value = serde_json::from_str(&original.payload).unwrap();
    body["unexpected"] = true.into();
    forged = original;
    forged.payload = body.to_string();
    assert!(verify_entry(&forged, &parsed.case_scope).is_err());
}
