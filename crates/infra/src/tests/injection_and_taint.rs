use super::*;

#[test]
fn detected_injection_cannot_expand_next_read_scope() {
    struct FollowLog(Mutex<usize>);
    streaming_test_model!(FollowLog);
    impl LegacyModel for FollowLog {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            let account = if *turns == 1 { "123" } else { "999" };
            Ok(ModelResponse {
                text: "done".into(),
                raw: format!("turn {}", *turns),
                calls: if *turns <= 2 {
                    vec![ProposedCall {
                        tool: Tool::SiemSearch,
                        args: BTreeMap::from([
                            ("source".into(), "splunk-prod".into()),
                            ("account".into(), account.into()),
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
        key: SigningKey::from_bytes(&[61u8; 32]),
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
    let case = engine.create_case(
            "Scope", "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z",
        ).unwrap();
    engine
        .investigate(&case.id, "check", &FollowLog(Mutex::new(0)))
        .unwrap();
    assert_eq!(*siem.calls.lock().unwrap(), 1);
    assert_eq!(engine.pending_approvals(&case.id).unwrap().len(), 1);
    let entries = store.entries(&case.id).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::InjectionDetected)
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::NeedsApproval)
    );
    engine.verify(&case.id).unwrap();
}

#[test]
fn scoped_internal_intel_uses_its_own_read_port() {
    struct Propose(Mutex<usize>);
    streaming_test_model!(Propose);
    impl LegacyModel for Propose {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            Ok(ModelResponse {
                text: "done".into(),
                raw: "internal lookup".into(),
                calls: if *turns == 1 {
                    vec![ProposedCall {
                        tool: Tool::ThreatIntelInternal,
                        args: BTreeMap::from([
                            ("source".into(), "misp-internal".into()),
                            ("ioc".into(), "example.com".into()),
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
        key: SigningKey::from_bytes(&[47u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let intel = FakeInternalIntel {
        calls: Mutex::new(0),
        source_id: "misp-internal".into(),
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
    .with_internal_intel(&intel)
    .unwrap();
    let scope = "v1;sources=misp-internal;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine.create_case("Internal intelligence", scope).unwrap();
    engine
        .investigate(&case.id, "lookup", &Propose(Mutex::new(0)))
        .unwrap();
    assert_eq!(*intel.calls.lock().unwrap(), 1);
    assert!(engine.pending_approvals(&case.id).unwrap().is_empty());
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::ToolResult && entry.evidence.is_some()
    }));
    engine.verify(&case.id).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn result_is_redacted_before_model_byte_limit() {
    struct BoundaryIntel;
    #[irmind_app::async_trait]
    impl InternalIntelPort for BoundaryIntel {
        fn source_id(&self) -> &'static str {
            "misp-internal"
        }

        async fn execute(
            &self,
            _call: &irmind_domain::AuthorizedCall,
            _cancel: &CancellationToken,
        ) -> Result<Vec<u8>, AppError> {
            Ok(b"aaaaaaapassword=supersecretvalue123".to_vec())
        }
    }

    struct BoundaryModel(Mutex<usize>);
    streaming_test_model!(BoundaryModel);
    impl LegacyModel for BoundaryModel {
        fn complete(&self, context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            if *turns == 2 {
                if context.contains("password=su") || context.contains("supersecret") {
                    return Err(AppError::Guard("secret crossed result limit".into()));
                }
                return Ok(ModelResponse {
                    text: "safe".into(),
                    calls: Vec::new(),
                    raw: "safe".into(),
                });
            }
            Ok(ModelResponse {
                text: String::new(),
                raw: "lookup".into(),
                calls: vec![ProposedCall {
                    tool: Tool::ThreatIntelInternal,
                    args: BTreeMap::from([
                        ("source".into(), "misp-internal".into()),
                        ("ioc".into(), "example.com".into()),
                    ]),
                }],
            })
        }
    }

    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[56u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let intel = BoundaryIntel;
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
    .with_internal_intel(&intel)
    .unwrap()
    .with_policy(
        PolicyRules {
            max_model_result_bytes: 18,
            ..PolicyRules::default()
        },
        "1".repeat(64),
    )
    .unwrap();
    let scope = "v1;sources=misp-internal;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine.create_case("Boundary", scope).unwrap();
    assert_eq!(
        engine
            .investigate(&case.id, "lookup", &BoundaryModel(Mutex::new(0)))
            .unwrap(),
        "safe"
    );
}

#[test]
fn tainted_release_requires_analyst_signature_and_signed_audit() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[93u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
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
    .unwrap();
    let case = engine.create_case("Taint", "local scope").unwrap();
    let provenance = Provenance::new([9; 32], Some(4), SourceKind::File);
    let challenge = provenance.approval_challenge(&case.id);
    let invalid = Tainted::from_external("secret".to_owned(), provenance.clone());
    assert!(engine.release_tainted(&case.id, invalid, &[0; 64]).is_err());
    let value = Tainted::from_external("secret".to_owned(), provenance);
    let signature = signer.sign(&challenge).unwrap();
    assert_eq!(
        engine.release_tainted(&case.id, value, &signature).unwrap(),
        "secret"
    );
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.kind == irmind_domain::AuditEventKind::TaintDeclassified)
            .count(),
        1
    );
    engine.verify(&case.id).unwrap();
}
