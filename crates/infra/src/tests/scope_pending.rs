use super::*;

#[test]
fn narrowed_policy_keeps_old_pending_auditable_but_blocks_its_approval() {
    struct OneCall(Mutex<Option<ProposedCall>>);
    streaming_test_model!(OneCall);
    impl LegacyModel for OneCall {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            Ok(ModelResponse {
                text: "synthetic".into(),
                raw: "one proposal".into(),
                calls: self.0.lock().map_err(storage)?.take().into_iter().collect(),
            })
        }
    }

    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[92u8; 32]),
        actor: Actor::Analyst,
    });
    let cloud = FakeCloudAudit(Mutex::new(0));
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
    .with_cloud_audit(&cloud)
    .unwrap();
    let ceiling = "v2;sources=aws-prod;accounts=account-a;projects=project-a;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine.create_case("Synthetic", ceiling).unwrap();
    let model = OneCall(Mutex::new(Some(ProposedCall {
        tool: Tool::CloudAuditEvents,
        args: BTreeMap::from([
            ("source".into(), "aws-prod".into()),
            ("project".into(), "project-b".into()),
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("event_name".into(), "AssumeRole".into()),
        ]),
    })));
    assert_eq!(
        engine
            .investigate(&case.id, "Check project-b", &model)
            .unwrap(),
        "synthetic"
    );
    assert_eq!(engine.pending_approvals(&case.id).unwrap().len(), 1);
    let policy = PolicyRules {
        scope: Some(irmind_domain::CaseScope::parse(ceiling).unwrap()),
        ..PolicyRules::default()
    };
    let engine = engine.with_policy(policy, "b".repeat(64)).unwrap();
    assert!(engine.verify(&case.id).is_ok());
    let pending = engine.pending_approvals(&case.id).unwrap();
    assert_eq!(pending.len(), 1);
    assert!(engine.approve(&case.id, &pending[0].id).is_err());
    assert_eq!(engine.pending_approvals(&case.id).unwrap().len(), 1);
    assert!(
        store
            .entries(&case.id)
            .unwrap()
            .iter()
            .all(|entry| entry.kind != irmind_domain::AuditEventKind::ToolResult)
    );
}
