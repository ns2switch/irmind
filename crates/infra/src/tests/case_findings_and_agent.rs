use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn agent_can_propose_but_only_analyst_can_confirm_evidence_finding() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let analyst_key = SigningKey::from_bytes(&[56u8; 32]);
    let agent_key = SigningKey::from_bytes(&[57u8; 32]);
    let analyst = Arc::new(TestSigner {
        actor: Actor::Analyst,
        key: analyst_key,
    });
    let agent = Arc::new(TestSigner {
        actor: Actor::Agent(irmind_domain::AgentId::parse("finding-agent").unwrap()),
        key: agent_key,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let attended = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                analyst.clone(),
                Arc::new(
                    LocalVerifier::from_signer(analyst.as_ref())
                        .with_trusted_key(&agent.actor(), &agent.public_key())
                        .unwrap(),
                ),
            ),
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let unattended = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                agent.clone(),
                Arc::new(
                    LocalVerifier::from_signer(analyst.as_ref())
                        .with_trusted_key(&agent.actor(), &agent.public_key())
                        .unwrap(),
                ),
            ),
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Unattended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = attended.create_case("IOC", "local only").unwrap();
    let hash = ingest_synthetic(
        &attended,
        store.as_ref(),
        parser.as_ref(),
        &case.id,
        br#"{"eventName":"Alert","sourceIPAddress":"198.51.100.9"}"#,
        "alert.json",
    );
    let model = FindingModel {
        hash: hash.clone(),
        turns: Mutex::new(0),
    };
    unattended
        .investigate(&case.id, "Investigate", &model)
        .unwrap();
    let findings = attended.findings(&case.id).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence_hash, hash);
    assert!(matches!(
        findings[0].details.as_ref(),
        Some(irmind_app::EntityDetails::Ioc { .. })
    ));
    assert!(!findings[0].confirmed);
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::FindingProposed
            && entry.origin == "model"
            && matches!(entry.actor, Actor::Agent(_))
    }));
    assert!(
        !attended
            .report(&case.id)
            .unwrap()
            .contains("- 198.51.100.9")
    );
    assert!(
        unattended
            .confirm_finding(&case.id, &findings[0].id)
            .is_err()
    );
    attended.confirm_finding(&case.id, &findings[0].id).unwrap();
    assert!(
        attended
            .report(&case.id)
            .unwrap()
            .contains("- 198.51.100.9")
    );
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::FindingConfirmed
            && matches!(entry.actor, Actor::Analyst)
    }));
}

#[test]
fn raw_record_pointer_selects_one_event_from_cloud_response() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[55u8; 32]),
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
    let case = engine.create_case("Cloud response", "local only").unwrap();
    let bytes = br#"{"events":[{"eventName":"First"},{"eventName":"Second"}]}"#;
    let hash = ingest_synthetic(
        &engine,
        store.as_ref(),
        parser.as_ref(),
        &case.id,
        bytes,
        "cloud-response.json",
    );
    let raw = store.raw_record(&case.id, &hash, 1).unwrap();
    assert!(raw.contains("Second"));
    assert!(!raw.contains("First"));
    engine.verify(&case.id).unwrap();
}

#[test]
fn failed_local_tool_call_has_signed_error_event() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[59u8; 32]),
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
    let case = engine
        .create_case("Missing evidence", "local only")
        .unwrap();
    assert!(
        engine
            .investigate(&case.id, "Read evidence", &MissingReadModel)
            .is_err()
    );
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::ToolError && entry.payload == "evidence_read"
    }));
    engine.verify(&case.id).unwrap();
}

#[test]
fn signed_case_call_quota_blocks_second_model_read() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[42u8; 32]),
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
    .unwrap()
    .with_policy(
        PolicyRules {
            max_tool_calls_per_case: 1,
            ..PolicyRules::default()
        },
        "0".repeat(64),
    )
    .unwrap();
    let case = engine.create_case("Quota", "local").unwrap();
    let model = RepeatingReadModel {
        turns: Mutex::new(0),
    };
    engine.investigate(&case.id, "check", &model).unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == irmind_domain::AuditEventKind::Allowed)
            .count(),
        1
    );
    assert!(
            entries
                .iter()
                .any(|e| e.kind == irmind_domain::AuditEventKind::Denied && e.payload.contains("quota"))
        );
    assert_eq!(engine.verify(&case.id).unwrap(), entries.len());
}

#[test]
fn signed_model_usage_stops_case_before_followup_tool_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[44u8; 32]),
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
    .unwrap()
    .with_policy(
        PolicyRules {
            max_model_tokens_per_case: 100,
            ..PolicyRules::default()
        },
        "1".repeat(64),
    )
    .unwrap();
    let case = engine.create_case("Budget", "local").unwrap();
    let model = RepeatingReadModel {
        turns: Mutex::new(0),
    };
    assert!(engine.investigate(&case.id, "check", &model).is_err());
    let entries = store.entries(&case.id).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.kind == irmind_domain::AuditEventKind::ModelUsage)
    );
    assert!(
        entries
            .iter()
            .any(|e| e.kind == irmind_domain::AuditEventKind::BudgetExceeded)
    );
    assert!(
        !entries
            .iter()
            .any(|e| e.kind == irmind_domain::AuditEventKind::Allowed)
    );
    engine.verify(&case.id).unwrap();
}

#[test]
fn signed_approval_executes_external_port_once_and_screens_next_context() {
    struct Propose(Mutex<usize>);
    streaming_test_model!(Propose);
    impl LegacyModel for Propose {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            let mut turns = self.0.lock().map_err(storage)?;
            *turns += 1;
            Ok(ModelResponse {
                text: String::new(),
                raw: "proposal".into(),
                calls: if *turns == 1 {
                    vec![ProposedCall {
                        tool: Tool::ThreatIntelExternal,
                        args: BTreeMap::from([("ioc".into(), "example.com".into())]),
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
        key: SigningKey::from_bytes(&[43u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let port = FakeExternalIntel {
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
    .with_threat_intel(&port);
    let case = engine.create_case("Intel", "local").unwrap();
    engine
        .investigate(&case.id, "lookup", &Propose(Mutex::new(0)))
        .unwrap();
    let request = engine.pending_approvals(&case.id).unwrap().remove(0);
    let outcome = engine.approve(&case.id, &request.id).unwrap();
    assert!(outcome.contains("evidence"));
    assert_eq!(*port.calls.lock().unwrap(), 1);
    assert!(engine.approve(&case.id, &request.id).is_err());
    let model = CaptureModel {
        seen: Mutex::new(String::new()),
    };
    engine.investigate(&case.id, "follow up", &model).unwrap();
    assert!(!model.seen.lock().unwrap().contains("alice@example.com"));
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::ToolResult
            && entry.payload.contains("ti_lookup_external")
    }));
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
