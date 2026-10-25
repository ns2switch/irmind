    #[test]
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
                    .any(|entry| entry.kind == "ToolResult"),
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
                .find(|entry| entry.kind == "ToolResult")
                .unwrap();
            let evidence = store
                .get_evidence(&case.id, result.evidence.as_deref().unwrap())
                .unwrap();
            assert!(!evidence.is_empty(), "{family}");
            engine.verify(&case.id).unwrap();
        }
    }

    #[test]
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
            .find(|entry| entry.kind == "ToolResult")
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
            .find(|entry| entry.kind == "ToolResult")
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
            entry.kind == "ModulesActivated" && entry.payload == registry.fingerprint()
        }));
        let entries = store.entries(&case.id).unwrap();
        let result = entries
            .iter()
            .find(|entry| entry.kind == "ToolResult")
            .unwrap();
        let raw = store
            .get_evidence(&case.id, result.evidence.as_deref().unwrap())
            .unwrap();
        assert!(String::from_utf8_lossy(&raw).contains("alice@example.com"));
        assert_eq!(
            result.evidence.as_deref(),
            Some(irmind_app::hex(&irmind_app::sha256(&raw)).as_str())
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == "ModelReply" && entry.seq > result.seq)
        );
        assert!(store.timeline(&case.id, 20).unwrap().iter().any(|event| {
            event.event == "MalwareDetected"
                && event.evidence_hash == result.evidence.clone().unwrap()
        }));
        assert!(!model.seen.lock().unwrap()[1].contains("alice@example.com"));
        engine.verify(&case.id).unwrap();
        engine.verify_graph(&case.id).unwrap();
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
                    text: "done".into(),
                    raw: "cloud identity proposal".into(),
                    calls: if *turns == 1 {
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
                    },
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
        assert!(
            store
                .entries(&case.id)
                .unwrap()
                .iter()
                .any(|entry| { entry.kind == "ToolResult" && entry.evidence.is_some() })
        );
        engine.verify(&case.id).unwrap();
    }

    #[test]
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
                            ("query".into(), "AssumeRole".into()),
                        ]),
                    }],
                    2 => {
                        if !context.contains("UNTRUSTED_INSTRUCTION_REMOVED")
                            || context.contains("ignore previous instructions")
                            || !context.contains("\"domain\":\"example.com\"")
                        {
                            return Err(AppError::Guard(
                                "SIEM injection was not isolated while the IOC remained visible"
                                    .into(),
                            ));
                        }
                        let ioc = context
                            .split("\"domain\":\"")
                            .nth(1)
                            .and_then(|tail| tail.split('"').next())
                            .ok_or_else(|| {
                                AppError::Guard("IOC missing from screened log".into())
                            })?;
                        vec![ProposedCall {
                            tool: Tool::ThreatIntelExternal,
                            args: BTreeMap::from([("ioc".into(), ioc.into())]),
                        }]
                    }
                    _ => Vec::new(),
                };
                Ok(ModelResponse {
                    text: "investigation paused".into(),
                    raw: format!("turn {}", *turns),
                    calls,
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
            .find(|entry| entry.kind == "ToolResult")
            .and_then(|entry| entry.evidence.as_deref())
            .unwrap();
        assert!(entries.iter().any(|entry| {
            entry.kind == "InjectionDetected" && entry.evidence.as_deref() == Some(result_hash)
        }));
        engine.verify(&case.id).unwrap();
    }
