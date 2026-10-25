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
                .any(|entry| entry.kind == "InjectionDetected")
        );
        assert!(entries.iter().any(|entry| entry.kind == "NeedsApproval"));
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
                .filter(|entry| entry.kind == "TaintDeclassified")
                .count(),
            1
        );
        engine.verify(&case.id).unwrap();
    }

    #[test]
    fn sealed_export_verifies_without_local_key_and_detects_tampering() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[9u8; 32]),
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
            .create_case("AWS alert", "account 123456789012")
            .unwrap();
        let cloudtrail = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","sourceIPAddress":"203.0.113.8"}]}"#;
        let hash = engine
            .ingest(&case.id, cloudtrail, "cloudtrail.json")
            .unwrap();
        let finding_id = engine
            .add_finding(&case.id, FindingKind::Ioc, "203.0.113.8", &hash)
            .unwrap();
        assert!(!engine.report(&case.id).unwrap().contains("- 203.0.113.8"));
        engine.confirm_finding(&case.id, &finding_id).unwrap();
        assert!(engine.report(&case.id).unwrap().contains("- 203.0.113.8"));
        let discarded = engine
            .add_finding(&case.id, FindingKind::Hypothesis, "False hypothesis", &hash)
            .unwrap();
        engine
            .dismiss_finding(&case.id, &discarded, "not supported by the event")
            .unwrap();
        assert!(engine.confirm_finding(&case.id, &discarded).is_err());
        assert!(
            !engine
                .report(&case.id)
                .unwrap()
                .contains("False hypothesis")
        );
        assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
            entry.kind == "GraphIndexed" && entry.payload.contains("graph=duckdb-graph-v3")
        }));
        assert!(
            store
                .graph_summary(&case.id)
                .unwrap()
                .contains("203.0.113.8")
        );
        let timeline = store.timeline(&case.id, 20).unwrap();
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].event, "AssumeRole");
        assert_eq!(timeline[0].evidence_hash, hash);
        engine.seal(&case.id).unwrap();
        let last = store.last_entry(&case.id).unwrap().unwrap();
        let seal = store.case_seal(&case.id).unwrap().unwrap();
        assert_ne!(seal.sig, last.sig);
        let path = root.path().join("export.json");
        let public_key = store.export_case(&case.id, &path).unwrap();
        assert_eq!(verify_export(&path).unwrap().0, public_key);
        assert_eq!(
            verify_export_expected(&path, Some(&public_key)).unwrap().0,
            public_key
        );
        assert!(matches!(
            verify_export_expected(&path, Some(&"0".repeat(64))),
            Err(AppError::Signature(_))
        ));
        assert_eq!(
            store
                .case_seal(&case.id)
                .unwrap()
                .unwrap()
                .analyst_key_fingerprint,
            public_key
        );
        let mut bundle: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let original = bundle.clone();
        bundle["seal"]["sig"] = serde_json::json!(last.sig);
        fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        assert!(verify_export(&path).is_err());
        bundle = original;
        bundle["evidence"][&hash] = serde_json::Value::String(BASE64.encode(b"tampered"));
        fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        assert!(matches!(
            verify_export(&path),
            Err(AppError::EvidenceMismatch(_))
        ));
    }

    #[test]
    fn oversized_export_is_rejected_before_parsing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("oversized.json");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_EXPORT_BYTES as u64 + 1).unwrap();
        assert!(verify_export(&path).is_err());
    }

    #[test]
    #[allow(clippy::panic)]
    fn approval_signature_cannot_be_reused_as_audit_signature() {
        let signer = LocalSigner {
            key: SigningKey::from_bytes(&[82u8; 32]),
            actor: Actor::Analyst,
        };
        let case = Case {
            id: CaseId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            title: "Replay".into(),
            severity: Severity::Medium,
            scope: "local scope".into(),
            sealed: false,
        };
        let irmind_domain::Decision::NeedsApproval(pending) = irmind_domain::evaluate(
            &case,
            ProposedCall {
                tool: Tool::ThreatIntelExternal,
                args: BTreeMap::from([("ioc".into(), "example.com".into())]),
            },
            4,
            ExecutionMode::Attended,
         1_700_000_000) else {
            panic!("expected pending approval")
        };
        let signature = signer.sign(&pending.challenge()).unwrap();
        assert!(verify_signature(&signer.public_key(), &pending.challenge(), &signature).is_ok());
        let audit_hash = sha256(b"irmind-audit-v2\0different-entry");
        assert!(verify_signature(&signer.public_key(), &audit_hash, &signature).is_err());
    }

    #[test]
    fn seal_recovers_each_crash_boundary_and_refuses_inconsistent_chain() {
        for crash_point in ["intent", "temporary", "rename", "directory_sync"] {
            let root = tempfile::tempdir().unwrap();
            let store = Arc::new(LocalStore::open(root.path()).unwrap());
            let signer = Arc::new(LocalSigner {
                key: SigningKey::from_bytes(&[73u8; 32]),
                actor: Actor::Analyst,
            });
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
            .unwrap();
            let case = engine.create_case("Crash test", "local scope").unwrap();
            engine.seal(&case.id).unwrap();
            let seal_path = root
                .path()
                .join("seals")
                .join(format!("{}.json", case.id.as_str()));
            let seal_bytes = fs::read(&seal_path).unwrap();
            store
                .conn()
                .unwrap()
                .execute(
                    "UPDATE cases SET seal_pending=1 WHERE id=?1",
                    [case.id.as_str()],
                )
                .unwrap();
            if matches!(crash_point, "intent" | "temporary") {
                fs::remove_file(&seal_path).unwrap();
            }
            let temporary = root
                .path()
                .join("seals")
                .join(format!(".{}.123.tmp", case.id.as_str()));
            if crash_point == "temporary" {
                fs::write(&temporary, &seal_bytes).unwrap();
            }
            drop(engine);
            drop(store);
            let recovered = LocalStore::open(root.path()).unwrap();
            assert!(
                recovered.case_seal(&case.id).unwrap().is_some(),
                "{crash_point}"
            );
            assert!(!temporary.exists(), "{crash_point}");
            let pending: i64 = recovered
                .conn()
                .unwrap()
                .query_row(
                    "SELECT seal_pending FROM cases WHERE id=?1",
                    [case.id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(pending, 0, "{crash_point}");
        }

        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[74u8; 32]),
            actor: Actor::Analyst,
        });
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
        .unwrap();
        let case = engine.create_case("Inconsistent", "local scope").unwrap();
        engine.seal(&case.id).unwrap();
        fs::remove_file(
            root.path()
                .join("seals")
                .join(format!("{}.json", case.id.as_str())),
        )
        .unwrap();
        store
            .conn()
            .unwrap()
            .execute(
                "UPDATE cases SET title='tampered', seal_pending=1 WHERE id=?1",
                [case.id.as_str()],
            )
            .unwrap();
        drop(engine);
        drop(store);
        let recovered = Arc::new(LocalStore::open(root.path()).unwrap());
        assert!(matches!(
            recovered.case_seal(&case.id),
            Err(AppError::InvalidChain(0))
        ));
        let engine = Engine::new(
            EnginePorts::new(
                recovered.clone(),
                recovered.clone(),
                recovered.clone(),
                recovered.clone(),
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
        .unwrap();
        assert!(engine.verify(&case.id).is_err());
    }

    #[test]
    fn crash_after_seal_transaction_without_seal_signature_is_inconsistent() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[75u8; 32]),
            actor: Actor::Analyst,
        });
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
        .unwrap();
        let case = engine
            .create_case("Crash before intent", "local scope")
            .unwrap();
        let last = store.last_entry(&case.id).unwrap().unwrap();
        let mut entry = SignedEntry {
            seq: last.seq + 1,
            case_id: case.id.as_str().into(),
            at: last.at + 1,
            actor: Actor::Analyst,
            origin: "analyst".into(),
            kind: "CaseSealed".into(),
            payload: String::new(),
            evidence: None,
            prev: last.hash,
            hash: [0; 32],
            sig: Vec::new(),
            public_key: signer.public_key(),
        };
        entry.hash = sha256(&entry.canonical());
        entry.sig = signer.sign(&entry.hash).unwrap();
        store
            .transact(&entry, CaseMutation::Seal(case.id.clone()))
            .unwrap();
        drop(engine);
        drop(store);
        let reopened = LocalStore::open(root.path()).unwrap();
        assert!(matches!(
            reopened.case_seal(&case.id),
            Err(AppError::InvalidChain(0))
        ));
    }
