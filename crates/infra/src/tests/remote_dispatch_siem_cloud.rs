use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn every_port_family_dispatches_signed_approval_through_registry() {
    struct OneCall(Mutex<Option<ProposedCall>>);
    streaming_test_model!(OneCall);
    impl LegacyModel for OneCall {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            Ok(ModelResponse {
                text: "done".into(),
                raw: "propose once".into(),
                calls: self.0.lock().map_err(storage)?.take().into_iter().collect(),
            })
        }
    }

    let scenarios = [
        (
            "siem",
            Tool::SiemSearch,
            BTreeMap::from([
                ("source".into(), "splunk-prod".into()),
                ("account".into(), "123".into()),
                ("from".into(), "2026-10-23T12:00:00Z".into()),
                ("to".into(), "2026-10-23T13:00:00Z".into()),
                ("query".into(), "AssumeRole".into()),
            ]),
        ),
        (
            "edr",
            Tool::EdrDetections,
            BTreeMap::from([
                ("source".into(), "edr-prod".into()),
                ("host".into(), "host-1".into()),
                ("from".into(), "2026-10-23T12:00:00Z".into()),
                ("to".into(), "2026-10-23T13:00:00Z".into()),
            ]),
        ),
        (
            "cloud",
            Tool::CloudAuditEvents,
            BTreeMap::from([
                ("source".into(), "aws-prod".into()),
                ("account".into(), "123456789012".into()),
                ("from".into(), "2026-10-23T12:00:00Z".into()),
                ("to".into(), "2026-10-23T13:00:00Z".into()),
                ("event_name".into(), "AssumeRole".into()),
            ]),
        ),
        (
            "ti",
            Tool::ThreatIntelExternal,
            BTreeMap::from([("ioc".into(), "example.com".into())]),
        ),
    ];

    for (family, tool, args) in scenarios {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[60u8; 32]),
            actor: Actor::Analyst,
        });
        let guard = Arc::new(MandatoryGuard::new().unwrap());
        let parser = Arc::new(JsonParser);
        let mut registry = ModuleRegistry::new();
        match family {
            "siem" => registry
                .add_siem(Box::new(FakeSiem {
                    calls: Mutex::new(0),
                    source_id: "splunk-prod".into(),
                }))
                .unwrap(),
            "edr" => registry
                .register(
                    Box::new(FakeEdr::new(
                        "edr-prod",
                        "host-1",
                        b"{\"eventName\":\"MalwareDetected\"}".to_vec(),
                        Arc::new(Mutex::new(0)),
                    )),
                    &ModuleConfig::new(),
                )
                .unwrap(),
            "cloud" => registry
                .add_cloud_audit(Box::new(FakeCloudAudit(Mutex::new(0))))
                .unwrap(),
            "ti" => registry
                .add_threat_intel(Box::new(FakeExternalIntel {
                    calls: Mutex::new(0),
                }))
                .unwrap(),
            _ => unreachable!(),
        }
        let engine = registry
            .bind(
                Engine::new(
                    EnginePorts::new(
                        store.clone(),
                        store.clone(),
                        store.clone(),
                        store.clone(),
                        CryptoPorts::new(
                            signer.clone(),
                            Arc::new(LocalVerifier::from_signer(signer.as_ref())),
                        ),
                        guard.clone(),
                        parser.clone(),
                    ),
                    ExecutionMode::Attended,
                    Arc::new(SystemClock),
                )
                .unwrap(),
            )
            .unwrap();
        let case = engine.create_case(family, "local").unwrap();
        engine
            .investigate(
                &case.id,
                "synthetic alert",
                &OneCall(Mutex::new(Some(ProposedCall { tool, args }))),
            )
            .unwrap();
        let pending = engine.pending_approvals(&case.id).unwrap();
        assert_eq!(pending.len(), 1, "{family}");
        assert!(
            !store
                .entries(&case.id)
                .unwrap()
                .iter()
                .any(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult),
            "{family}"
        );
        assert!(
            engine
                .approve(&case.id, &pending[0].id)
                .unwrap()
                .contains("evidence"),
            "{family}"
        );
        let entries = store.entries(&case.id).unwrap();
        let kinds = entries
            .iter()
            .map(|entry| entry.kind.as_str())
            .collect::<Vec<_>>();
        for expected in [
            "Proposal",
            "NeedsApproval",
            "ApprovalGranted",
            "ToolDispatch",
            "ToolResult",
        ] {
            assert!(kinds.contains(&expected), "{family}: missing {expected}");
        }
        let result = entries
            .iter()
            .find(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
            .unwrap();
        let evidence = store
            .get_evidence(&case.id, result.evidence.as_deref().unwrap())
            .unwrap();
        assert!(!evidence.is_empty(), "{family}");
        engine.verify(&case.id).unwrap();
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn scoped_siem_read_uses_authorized_port_and_keeps_raw_evidence_local() {
    struct Propose(Mutex<usize>);
    streaming_test_model!(Propose);
    impl LegacyModel for Propose {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            Ok(ModelResponse {
                text: "done".into(),
                raw: "siem proposal".into(),
                calls: if *turns == 1 {
                    vec![ProposedCall {
                        tool: Tool::SiemSearch,
                        args: BTreeMap::from([
                            ("source".into(), "splunk-prod".into()),
                            ("account".into(), "123".into()),
                            ("from".into(), "2026-10-23T12:00:00Z".into()),
                            ("to".into(), "2026-10-23T13:00:00Z".into()),
                            ("query".into(), "AssumeRole".into()),
                        ]),
                    }]
                } else {
                    Vec::new()
                },
            })
        }
    }
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[45u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
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
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_siem(&siem)
    .unwrap();
    let scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine.create_case("SIEM", scope).unwrap();
    engine
        .investigate(&case.id, "Find AssumeRole", &Propose(Mutex::new(0)))
        .unwrap();
    assert_eq!(*siem.calls.lock().unwrap(), 1);
    assert!(engine.pending_approvals(&case.id).unwrap().is_empty());
    let result = store
        .entries(&case.id)
        .unwrap()
        .into_iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
        .unwrap();
    let raw = store
        .get_evidence(&case.id, result.evidence.as_deref().unwrap())
        .unwrap();
    assert!(String::from_utf8_lossy(&raw).contains("alice@example.com"));
    assert!(store.timeline(&case.id, 20).unwrap().iter().any(|event| {
        event.event == "AssumeRole" && event.evidence_hash == result.evidence.clone().unwrap()
    }));
    let model = CaptureModel {
        seen: Mutex::new(String::new()),
    };
    engine.investigate(&case.id, "Follow up", &model).unwrap();
    assert!(!model.seen.lock().unwrap().contains("alice@example.com"));
    engine.verify(&case.id).unwrap();
}

#[test]
fn scoped_cloud_read_is_audited_and_redacted() {
    struct ProposeCloud(Mutex<usize>);
    streaming_test_model!(ProposeCloud);
    impl LegacyModel for ProposeCloud {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            Ok(ModelResponse {
                text: "done".into(),
                raw: "cloud proposal".into(),
                calls: if *turns == 1 {
                    vec![ProposedCall {
                        tool: Tool::CloudAuditEvents,
                        args: BTreeMap::from([
                            ("source".into(), "aws-prod".into()),
                            ("account".into(), "123456789012".into()),
                            ("from".into(), "2026-10-23T12:00:00Z".into()),
                            ("to".into(), "2026-10-23T13:00:00Z".into()),
                            ("event_name".into(), "AssumeRole".into()),
                        ]),
                    }]
                } else {
                    Vec::new()
                },
            })
        }
    }
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[54u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
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
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_cloud_audit(&cloud)
    .unwrap();
    let scope = "v1;sources=aws-prod;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine.create_case("Cloud", scope).unwrap();
    engine
        .investigate(&case.id, "Find AssumeRole", &ProposeCloud(Mutex::new(0)))
        .unwrap();
    assert_eq!(*cloud.0.lock().unwrap(), 1);
    let result = store
        .entries(&case.id)
        .unwrap()
        .into_iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
        .unwrap();
    let raw = store
        .get_evidence(&case.id, result.evidence.as_deref().unwrap())
        .unwrap();
    assert!(String::from_utf8_lossy(&raw).contains("alice@example.com"));
    assert!(store.timeline(&case.id, 20).unwrap().iter().any(|event| {
        event.event == "AssumeRole" && event.evidence_hash == result.evidence.clone().unwrap()
    }));
    let model = CaptureModel {
        seen: Mutex::new(String::new()),
    };
    engine.investigate(&case.id, "Follow up", &model).unwrap();
    assert!(!model.seen.lock().unwrap().contains("alice@example.com"));
    engine.verify(&case.id).unwrap();
}
