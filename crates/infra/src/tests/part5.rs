    #[test]
    fn agent_signature_cannot_resolve_analyst_approval() {
        let analyst = SigningKey::from_bytes(&[11u8; 32]);
        let agent = SigningKey::from_bytes(&[12u8; 32]);
        let case = Case {
            id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            title: "x".into(),
            severity: Severity::Medium,
            scope: "local".into(),
            sealed: false,
        };
        let proposal = ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.com".into())]),
        };
        let Decision::NeedsApproval(pending) =
            evaluate(&case, proposal.clone(), 2, ExecutionMode::Unattended, 1_700_000_000)
        else {
            panic!("expected pending approval");
        };
        let challenge = pending.challenge();
        let verifier = LocalAnalystVerifier(analyst.verifying_key());
        assert!(
            pending
                .resolve(&agent.sign(&challenge).to_bytes(), &verifier, 1_700_000_000)
                .is_err()
        );
        let Decision::NeedsApproval(pending) =
            evaluate(&case, proposal, 2, ExecutionMode::Unattended, 1_700_000_000)
        else {
            panic!("expected pending approval");
        };
        assert!(
            pending
                .resolve(&analyst.sign(&challenge).to_bytes(), &verifier, 1_700_000_000)
                .is_ok()
        );
        let Decision::NeedsApproval(pending) = evaluate(
            &case,
            ProposedCall {
                tool: Tool::ThreatIntelExternal,
                args: BTreeMap::from([("ioc".into(), "example.com".into())]),
            },
            2,
            ExecutionMode::Unattended,
         1_700_000_000) else {
            panic!("expected pending approval");
        };
        let recovered = irmind_domain::PendingApproval::recover(
            &case,
            ExecutionMode::Unattended,
            &pending.challenge(),
         1_700_000_000)
        .unwrap();
        assert_eq!(recovered.challenge(), pending.challenge());
        assert!(
            pending
                .reject(
                    &agent.sign(&recovered.rejection_challenge()).to_bytes(),
                    &verifier
                )
                .is_err()
        );
    }

    #[test]
    fn analyst_resolves_persistent_agent_requests_without_external_execution() {
        let root = tempfile::tempdir().unwrap();
        let analyst_key = SigningKey::from_bytes(&[51u8; 32]);
        let agent_key = SigningKey::from_bytes(&[52u8; 32]);
        let analyst = Arc::new(TestSigner {
            actor: Actor::Analyst,
            key: analyst_key,
        });
        let agent = Arc::new(TestSigner {
            actor: Actor::Agent(irmind_domain::AgentId::parse("watcher-1").unwrap()),
            key: agent_key,
        });
        let guard = Arc::new(MandatoryGuard::new().unwrap());
        let parser = Arc::new(JsonParser);
        let case_id = {
            let store = Arc::new(LocalStore::open(root.path()).unwrap());
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
            let case = attended.create_case("Approval", "local evidence").unwrap();
            let model = ObedientModel {
                seen: Mutex::new(Vec::new()),
            };
            unattended
                .investigate(&case.id, "Investigate", &model)
                .unwrap();
            let pending = attended.pending_approvals(&case.id).unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].tool, Tool::ThreatIntelExternal);
            assert_eq!(
                pending[0].args.get("ioc").map(String::as_str),
                Some("attacker.example")
            );
            assert!(attended.seal(&case.id).is_err());
            assert!(unattended.approve(&case.id, &pending[0].id).is_err());
            case.id
        };
        let reopened = Arc::new(LocalStore::open(root.path()).unwrap());
        let attended = Engine::new(
            EnginePorts::new(
                reopened.clone(),
                reopened.clone(),
                reopened.clone(),
                reopened.clone(),
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
                reopened.clone(),
                reopened.clone(),
                reopened.clone(),
                reopened.clone(),
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
        let first = attended.pending_approvals(&case_id).unwrap().remove(0);
        assert!(
            attended
                .approve(&case_id, &first.id)
                .unwrap()
                .contains("no request was sent")
        );
        assert!(attended.approve(&case_id, &first.id).is_err());
        assert!(attended.pending_approvals(&case_id).unwrap().is_empty());
        let model = ObedientModel {
            seen: Mutex::new(Vec::new()),
        };
        unattended
            .investigate(&case_id, "Investigate again", &model)
            .unwrap();
        let second = attended.pending_approvals(&case_id).unwrap().remove(0);
        let before_invalid = reopened.entries(&case_id).unwrap().len();
        assert!(
            attended
                .edit_approval(
                    &case_id,
                    &second.id,
                    BTreeMap::from([("unexpected".into(), "value".into())])
                )
                .is_err()
        );
        assert!(
            unattended
                .edit_approval(
                    &case_id,
                    &second.id,
                    BTreeMap::from([("ioc".into(), "edited.example".into())])
                )
                .is_err()
        );
        assert_eq!(reopened.entries(&case_id).unwrap().len(), before_invalid);
        assert!(
            attended
                .edit_approval(
                    &case_id,
                    &second.id,
                    BTreeMap::from([("ioc".into(), "edited.example".into())])
                )
                .unwrap()
                .contains("no tool was executed")
        );
        let replacement = attended.pending_approvals(&case_id).unwrap().remove(0);
        assert_ne!(replacement.id, second.id);
        assert_eq!(replacement.mode, ExecutionMode::Unattended);
        assert_eq!(
            replacement.args.get("ioc").map(String::as_str),
            Some("edited.example")
        );
        assert!(attended.approve(&case_id, &second.id).is_err());
        assert!(
            attended
                .deny(&case_id, &replacement.id, "out of scope")
                .is_ok()
        );
        assert!(attended.pending_approvals(&case_id).unwrap().is_empty());
        let entries = reopened.entries(&case_id).unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == "ApprovalGranted" && entry.actor == Actor::Analyst)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == "ApprovalDenied" && entry.actor == Actor::Analyst)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == "Proposal" && entry.origin == "analyst")
        );
        assert!(!entries.iter().any(|entry| entry.kind == "ToolResult"));
        assert_eq!(attended.verify(&case_id).unwrap(), entries.len());
        attended.seal(&case_id).unwrap();
    }

    #[test]
    fn forged_approval_without_challenge_signature_fails_verification() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[61u8; 32]),
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
        let case = engine.create_case("Approval", "local").unwrap();
        let model = ObedientModel {
            seen: Mutex::new(Vec::new()),
        };
        engine.investigate(&case.id, "Inspect", &model).unwrap();
        let id = engine.pending_approvals(&case.id).unwrap().remove(0).id;
        let last = store.last_entry(&case.id).unwrap().unwrap();
        let mut forged = SignedEntry {
            seq: last.seq + 1,
            case_id: case.id.as_str().into(),
            at: last.at,
            actor: Actor::Analyst,
            origin: "analyst".into(),
            kind: "ApprovalGranted".into(),
            payload: serde_json::json!({"version":1,"id":id,"signature":"00","reason":null,"executed":false}).to_string(),
            evidence: None,
            prev: last.hash,
            hash: [0; 32],
            sig: Vec::new(),
            public_key: signer.public_key(),
        };
        forged.hash = sha256(&forged.canonical());
        forged.sig = signer.sign(&forged.hash).unwrap();
        store.append(&forged).unwrap();
        assert!(
            matches!(engine.verify(&case.id), Err(AppError::InvalidChain(seq)) if seq == forged.seq)
        );
    }

    #[test]
    fn concurrent_ingest_serializes_a_case() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalStore>();
        assert_send_sync::<Engine<'_>>();
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[13u8; 32]),
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
        let case = engine.create_case("Concurrent", "local").unwrap();
        std::thread::scope(|scope| {
            for number in 0..4 {
                let id = case.id.clone();
                let engine = &engine;
                scope.spawn(move || {
                    let payload = format!("{{\"eventName\":\"Read\",\"host\":\"host-{number}\"}}");
                    engine
                        .ingest(&id, payload.as_bytes(), "event.json")
                        .unwrap();
                });
            }
        });
        assert_eq!(engine.verify(&case.id).unwrap(), 9);
    }

    #[test]
    fn analyst_and_agent_entries_use_distinct_keys_in_one_export() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let analyst_key = SigningKey::from_bytes(&[21u8; 32]);
        let agent_key = SigningKey::from_bytes(&[22u8; 32]);
        let analyst = Arc::new(TestSigner {
            actor: Actor::Analyst,
            key: analyst_key,
        });
        let agent = Arc::new(TestSigner {
            actor: Actor::Agent(irmind_domain::AgentId::parse("watcher-1").unwrap()),
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
        let case = attended.create_case("Alert", "local evidence").unwrap();
        assert!(matches!(
            unattended.ingest(&case.id, b"{}", "log.json"),
            Err(AppError::PendingApproval(_))
        ));
        unattended
            .investigate(&case.id, "Inspect local evidence", &QuietModel)
            .unwrap();
        let entries = store.entries(&case.id).unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| matches!(entry.actor, Actor::Agent(_)))
        );
        assert!(entries.iter().any(|entry| entry.actor == Actor::Analyst));
        attended.seal(&case.id).unwrap();
        let path = root.path().join("mixed.json");
        CaseExporter::export_case(store.as_ref(), &case.id, &path, &CancellationToken::new()).unwrap();
        assert!(verify_export(&path).is_ok());
    }

    #[test]
    fn legacy_sqlite_graph_moves_to_duckdb() {
        let root = tempfile::tempdir().unwrap();
        let id = {
            let store = Arc::new(LocalStore::open(root.path()).unwrap());
            let signer = Arc::new(LocalSigner {
                key: SigningKey::from_bytes(&[31u8; 32]),
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
            let case = engine.create_case("Migration", "local").unwrap();
            let bytes = b"{\"eventName\":\"AssumeRole\",\"sourceIPAddress\":\"203.0.113.8\"}";
            let hash = hex(&sha256(bytes));
            store.put_evidence(&case.id, &hash, bytes).unwrap();
            let conn = store.conn().unwrap();
            conn.execute_batch(
                "CREATE TABLE graph_index (case_id TEXT, hash TEXT, records INTEGER);
                 CREATE TABLE graph_events (case_id TEXT, hash TEXT, record_index INTEGER, at TEXT, event TEXT);
                 CREATE TABLE graph_observations (case_id TEXT, hash TEXT, record_index INTEGER, at TEXT, event TEXT, kind TEXT, value TEXT);
                 CREATE TABLE graph_nodes (case_id TEXT, kind TEXT, value TEXT, first_seen TEXT, last_seen TEXT, count INTEGER);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO graph_index VALUES (?1,?2,1)",
                params![case.id.as_str(), hash],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO graph_events VALUES (?1,?2,0,'2026-10-23T12:00:00Z','AssumeRole')",
                params![case.id.as_str(), hash],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO graph_observations VALUES (?1,?2,0,'2026-10-23T12:00:00Z','AssumeRole','ip','203.0.113.8')",
                params![case.id.as_str(), hash],
            )
            .unwrap();
            case.id
        };
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        assert!(store.graph_summary(&id).unwrap().contains("203.0.113.8"));
        assert_eq!(store.timeline(&id, 10).unwrap()[0].event, "AssumeRole");
        assert!(
            root.path()
                .join("graph")
                .join(format!("{}.duckdb", id.as_str()))
                .exists()
        );
        let legacy: i64 = store
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='graph_index'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy, 0);
        drop(store);
        let reopened = Arc::new(LocalStore::open(root.path()).unwrap());
        assert_eq!(reopened.timeline(&id, 10).unwrap().len(), 1);
    }
