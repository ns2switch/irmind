use super::*;

#[test]
fn analyst_siem_alert_uses_policy_custody_and_redaction() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[55u8; 32]),
        actor: Actor::Analyst,
    });
    let siem = FakeSiem {
        calls: Mutex::new(0),
        source_id: "splunk-prod".into(),
    };
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_siem(&siem)
    .unwrap();
    let scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine.create_case("alert", scope).unwrap();
    let proposal = ProposedCall {
        tool: Tool::SiemGetAlert,
        args: BTreeMap::from([
            ("source".into(), "splunk-prod".into()),
            ("account".into(), "123".into()),
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("alert_id".into(), "alert-1".into()),
        ]),
    };
    let visible = engine
        .request_tool_as_analyst(&case.id, proposal, &CancellationToken::new())
        .unwrap();
    assert_eq!(*siem.calls.lock().unwrap(), 1);
    assert!(!visible.contains("alice@example.com"));
    let entries = store.entries(&case.id).unwrap();
    assert!(entries.iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::Proposal && entry.origin == "analyst"
    }));
    let result = entries
        .iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
        .unwrap();
    let raw = store
        .get_evidence(&case.id, result.evidence.as_deref().unwrap())
        .unwrap();
    assert!(
        raw.windows(b"alice@example.com".len())
            .any(|window| window == b"alice@example.com")
    );
    engine.verify(&case.id).unwrap();
}
