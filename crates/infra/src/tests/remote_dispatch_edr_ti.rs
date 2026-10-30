use super::*;

#[test]
fn scoped_edr_read_is_audited_indexed_and_redacted() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[58u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let calls = Arc::new(Mutex::new(0));
    let mut registry = ModuleRegistry::new();
    registry
            .register(Box::new(FakeEdr::new(
                "edr-prod",
                "host-1",
                b"{\"eventName\":\"MalwareDetected\",\"host\":\"host-1\",\"email\":\"alice@example.com\"}".to_vec(),
                Arc::clone(&calls),
            )), &ModuleConfig::new())
            .unwrap();
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
    let case = engine
            .create_case(
                "EDR alert",
                "v1;sources=edr-prod;accounts=;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z",
            )
            .unwrap();
    let model = EdrModel {
        turns: Mutex::new(0),
        seen: Mutex::new(Vec::new()),
    };
    engine.investigate(&case.id, "Investigate", &model).unwrap();
    assert_eq!(*calls.lock().unwrap(), 1);
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::ModulesActivated
            && entry.payload == registry.fingerprint()
    }));
    let entries = store.entries(&case.id).unwrap();
    let result = entries
        .iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
        .unwrap();
    let raw = store
        .get_evidence(&case.id, result.evidence.as_deref().unwrap())
        .unwrap();
    assert!(String::from_utf8_lossy(&raw).contains("alice@example.com"));
    assert_eq!(
        result.evidence.as_deref(),
        Some(irmind_app::hex(&irmind_app::sha256(&raw)).as_str())
    );
    assert!(entries.iter().any(
        |entry| entry.kind == irmind_domain::AuditEventKind::ModelReply && entry.seq > result.seq
    ));
    assert!(store.timeline(&case.id, 20).unwrap().is_empty());
    assert!(!model.seen.lock().unwrap()[1].contains("alice@example.com"));
    engine.verify(&case.id).unwrap();
    assert!(
        store
            .get_evidence(&case.id, result.evidence.as_deref().unwrap())
            .is_ok()
    );
}

#[test]
fn cloud_identity_uses_scoped_read_port() {
    struct ProposeIdentity(Mutex<usize>);
    streaming_test_model!(ProposeIdentity);
    impl LegacyModel for ProposeIdentity {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            Ok(ModelResponse {
                truncated: false,
                text: "done".into(),
                raw: "cloud identity proposal".into(),
                calls: model_calls(if *turns == 1 {
                    vec![ProposedCall {
                        tool: Tool::CloudIdentity,
                        args: BTreeMap::from([
                            ("source".into(), "aws-prod".into()),
                            ("account".into(), "123456789012".into()),
                            ("kind".into(), "role".into()),
                            ("name".into(), "Admin".into()),
                        ]),
                    }]
                } else {
                    Vec::new()
                }),
            })
        }
    }
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[55u8; 32]),
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
    let case = engine.create_case("Identity", scope).unwrap();
    engine
        .investigate(&case.id, "Inspect Admin", &ProposeIdentity(Mutex::new(0)))
        .unwrap();
    assert_eq!(*cloud.0.lock().unwrap(), 1);
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::ToolResult && entry.evidence.is_some()
    }));
    engine.verify(&case.id).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn malicious_siem_record_cannot_dispatch_external_intel() {
    struct ObeysInjectedTool(Mutex<usize>);
    streaming_test_model!(ObeysInjectedTool);
    impl LegacyModel for ObeysInjectedTool {
        fn complete(&self, context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            let calls = match *turns {
                1 => vec![ProposedCall {
                    tool: Tool::SiemSearch,
                    args: BTreeMap::from([
                        ("source".into(), "splunk-prod".into()),
                        ("account".into(), "123".into()),
                        ("from".into(), "2026-10-23T12:00:00Z".into()),
                        ("to".into(), "2026-10-23T13:00:00Z".into()),
                        ("field".into(), "event_name".into()),
                        ("operator".into(), "eq".into()),
                        ("value".into(), "AssumeRole".into()),
                    ]),
                }],
                2 => {
                    if !context.contains("UNTRUSTED_INSTRUCTION_REMOVED")
                        || context.contains("ignore previous instructions")
                        || !context.contains("\"domain\":\"example.com\"")
                    {
                        return Err(AppError::Guard(
                            "SIEM injection was not isolated while the IOC remained visible".into(),
                        ));
                    }
                    let ioc = context
                        .split("\"domain\":\"")
                        .nth(1)
                        .and_then(|tail| tail.split('"').next())
                        .ok_or_else(|| AppError::Guard("IOC missing from screened log".into()))?;
                    vec![ProposedCall {
                        tool: Tool::ThreatIntelExternal,
                        args: BTreeMap::from([("ioc".into(), ioc.into())]),
                    }]
                }
                _ => Vec::new(),
            };
            Ok(ModelResponse {
                truncated: false,
                text: "investigation paused".into(),
                raw: format!("turn {}", *turns),
                calls: model_calls(calls),
            })
        }
    }
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[46u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let siem = FakeSiem {
        calls: Mutex::new(0),
        source_id: "splunk-prod".into(),
    };
    let intel = FakeExternalIntel {
        calls: Mutex::new(0),
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
    .unwrap()
    .with_threat_intel(&intel);
    let scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine.create_case("Injected SIEM", scope).unwrap();
    engine
        .investigate(&case.id, "check", &ObeysInjectedTool(Mutex::new(0)))
        .unwrap();
    assert_eq!(*siem.calls.lock().unwrap(), 1);
    assert_eq!(*intel.calls.lock().unwrap(), 0);
    assert_eq!(engine.pending_approvals(&case.id).unwrap().len(), 1);
    let entries = store.entries(&case.id).unwrap();
    let result_hash = entries
        .iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
        .and_then(|entry| entry.evidence.as_deref())
        .unwrap();
    assert!(entries.iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::InjectionDetected
            && entry.evidence.as_deref() == Some(result_hash)
    }));
    engine.verify(&case.id).unwrap();
}
