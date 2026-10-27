use super::*;

#[test]
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
fn graph_queries_keep_entity_context_and_source_records() {
    struct BrokenParser;
    impl EventParser for BrokenParser {
        fn version(&self) -> &'static str {
            "json-cloudtrail-v1"
        }
        fn parse_each(
            &self,
            _source: &str,
            _bytes: &[u8],
            _cancel: &CancellationToken,
            _emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
        ) -> Result<usize, AppError> {
            Ok(0)
        }
    }
    struct GraphModel;
    streaming_test_model!(GraphModel);
    impl LegacyModel for GraphModel {
        fn complete(&self, context: &str) -> Result<ModelResponse, AppError> {
            if context.contains("Tool result:") {
                return Ok(ModelResponse {
                    text: "Investigation complete.".into(),
                    calls: Vec::new(),
                    raw: "final".into(),
                });
            }
            Ok(ModelResponse {
                text: String::new(),
                calls: vec![ProposedCall {
                    tool: Tool::Neighbors,
                    args: BTreeMap::from([
                        ("kind".into(), "ip".into()),
                        ("value".into(), "203.0.113.8".into()),
                        ("limit".into(), "10".into()),
                    ]),
                }],
                raw: "neighbors proposal".into(),
            })
        }
    }
    struct RawModel {
        hash: String,
    }
    streaming_test_model!(RawModel);
    impl LegacyModel for RawModel {
        fn complete(&self, context: &str) -> Result<ModelResponse, AppError> {
            if context.contains("Tool result:") {
                assert!(!context.contains("supersecret12345"));
                assert!(context.contains("<SECRET_"));
                return Ok(ModelResponse {
                    text: "Screened.".into(),
                    calls: Vec::new(),
                    raw: "screened".into(),
                });
            }
            Ok(ModelResponse {
                text: String::new(),
                calls: vec![ProposedCall {
                    tool: Tool::RawRecords,
                    args: BTreeMap::from([
                        ("hash".into(), self.hash.clone()),
                        ("index".into(), "0".into()),
                    ]),
                }],
                raw: "raw proposal".into(),
            })
        }
    }
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[41u8; 32]),
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
    let case = engine.create_case("Graph", "local").unwrap();
    let source = br#"{"Records":[
            {"eventTime":"2026-10-23T10:00:00Z","eventName":"AssumeRole","sourceIPAddress":"203.0.113.8","password":"supersecret12345","message":"rare hidden marker","userIdentity":{"arn":"arn:aws:iam::123456789012:role/Admin"}},
            {"eventTime":"2026-10-23T11:00:00Z","eventName":"GetObject","sourceIPAddress":"203.0.113.8","userName":"alice"},
            {"eventTime":"2026-10-23T12:00:00Z","eventName":"Login","sourceIPAddress":"198.51.100.7","userName":"bob"}
        ]}"#;
    let hash = engine.ingest(&case.id, source, "cloudtrail.json").unwrap();
    let entity = store.entity_lookup(&case.id, "ip", "203.0.113.8").unwrap();
    assert!(entity.contains("2 observations"));
    assert!(entity.contains(&format!("source={hash}#0")));
    assert!(entity.contains(&format!("source={hash}#1")));
    let neighbors = store.neighbors(&case.id, "ip", "203.0.113.8", 10).unwrap();
    assert!(neighbors.contains("co-observed"));
    assert!(neighbors.contains("role arn:aws:iam::123456789012:role/Admin"));
    assert!(neighbors.contains("user alice"));
    assert!(!neighbors.contains("bob"));
    assert!(neighbors.contains(&format!("source={hash}#0")));
    let activity = store
        .entity_timeline(&case.id, "ip", "203.0.113.8", 1)
        .unwrap();
    assert!(activity.contains("GetObject"));
    assert!(!activity.contains("AssumeRole"));
    let path = store
        .graph_path(
            &case.id,
            ("role", "arn:aws:iam::123456789012:role/Admin"),
            ("user", "alice"),
        )
        .unwrap();
    assert_eq!(path.lines().count(), 2);
    assert!(path.contains(&format!("{hash}#0")));
    assert!(path.contains(&format!("{hash}#1")));
    let search = store.text_search(&case.id, "GetObject", 10).unwrap();
    assert!(search.contains(&format!("source={hash}#1")));
    assert!(!search.contains(&format!("source={hash}#0")));
    let injected = store
        .text_search(&case.id, "'; DROP TABLE events; --", 10)
        .unwrap();
    assert!(injected.contains("no indexed matches"));
    assert!(store.text_search(&case.id, "GetObject", 10).is_ok());
    let entity_search = store.text_search(&case.id, "alice", 10).unwrap();
    assert!(entity_search.contains(&format!("source={hash}#1")));
    let free_text = store
        .text_search(&case.id, "rare hidden marker", 10)
        .unwrap();
    assert!(free_text.contains(&format!("source={hash}#0")));
    let record = store.raw_record(&case.id, &hash, 0).unwrap();
    assert!(record.contains("AssumeRole"));
    assert!(record.contains("203.0.113.8"));
    assert!(record.contains("supersecret12345"));
    assert!(!record.contains("GetObject"));
    assert!(matches!(
        store.raw_record(&case.id, &hash, 99),
        Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::RecordPointerIsNotIndexedInThisCase
        )))
    ));
    assert!(matches!(
        store.neighbors(&case.id, "ip", "203.0.113.8", 1000),
        Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::InvalidGraphQueryArguments
        )))
    ));
    assert_eq!(
        engine
            .investigate(&case.id, "Investigate", &GraphModel)
            .unwrap(),
        "Investigation complete."
    );
    assert_eq!(
        engine
            .investigate(&case.id, "Read record", &RawModel { hash: hash.clone() })
            .unwrap(),
        "Screened."
    );
    let entries = store.entries(&case.id).unwrap();
    assert!(entries.iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::Proposal && entry.payload.contains("neighbors")
    }));
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::Allowed)
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
    );
    assert_eq!(engine.verify(&case.id).unwrap(), entries.len());
    assert_eq!(engine.verify_graph(&case.id).unwrap(), 3);
    engine.seal(&case.id).unwrap();
    let audit_count = store.entries(&case.id).unwrap().len();
    store
        .graph
        .connect(&case.id)
        .unwrap()
        .execute(
            "UPDATE record_texts SET text='tampered' WHERE hash=?1 AND record_index=0",
            duckdb::params![hash],
        )
        .unwrap();
    assert!(engine.verify_graph(&case.id).is_err());
    assert_eq!(engine.rebuild_graph(&case.id).unwrap(), 3);
    assert_eq!(engine.verify_graph(&case.id).unwrap(), 3);
    store
        .graph
        .connect(&case.id)
        .unwrap()
        .execute(
            "DELETE FROM record_terms WHERE hash=?1 AND term='rare'",
            duckdb::params![hash],
        )
        .unwrap();
    assert!(engine.verify_graph(&case.id).is_err());
    assert_eq!(engine.rebuild_graph(&case.id).unwrap(), 3);
    assert_eq!(engine.verify_graph(&case.id).unwrap(), 3);
    let broken = Engine::new(
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
            Arc::new(BrokenParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    assert!(broken.rebuild_graph(&case.id).is_err());
    assert_eq!(engine.verify_graph(&case.id).unwrap(), 3);
    store
        .graph
        .connect(&case.id)
        .unwrap()
        .execute(
            "DELETE FROM record_texts WHERE hash=?1 AND record_index=0",
            duckdb::params![hash],
        )
        .unwrap();
    assert!(
        store
            .text_search(&case.id, "rare hidden marker", 10)
            .is_err()
    );
    assert_eq!(engine.rebuild_graph(&case.id).unwrap(), 3);
    assert_eq!(engine.verify_graph(&case.id).unwrap(), 3);
    assert_eq!(store.entries(&case.id).unwrap().len(), audit_count);
    assert_eq!(engine.verify(&case.id).unwrap(), audit_count);
}

#[test]
fn injected_clock_controls_signed_case_event_times() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[94u8; 32]),
        actor: Actor::Analyst,
    });
    let clock = Arc::new(FixedClock::new(1_700_000_000));
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
        clock.clone(),
    )
    .unwrap();
    let case = engine.create_case("Clock", "local").unwrap();
    clock.set(1_700_000_001);
    engine.change_scope(&case.id, "local-updated").unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(entries.first().unwrap().at, 1_700_000_000);
    assert_eq!(entries.last().unwrap().at, 1_700_000_001);
    assert_eq!(engine.verify(&case.id).unwrap(), entries.len());
}

#[test]
fn injected_clock_rejects_expired_approval_before_remote_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[95u8; 32]),
        actor: Actor::Analyst,
    });
    let clock = Arc::new(FixedClock::new(1_700_000_000));
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
        clock.clone(),
    )
    .unwrap();
    let case = engine.create_case("Expiry", "local").unwrap();
    engine
        .investigate(
            &case.id,
            "Inspect",
            &ObedientModel {
                seen: Mutex::new(Vec::new()),
            },
        )
        .unwrap();
    let pending = engine.pending_approvals(&case.id).unwrap();
    assert_eq!(pending.len(), 1);
    clock.set(1_700_000_301);
    assert!(matches!(
        engine.approve(&case.id, &pending[0].id),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::SignatureAnalystApprovalSignatureIsInvalid
        ))
    ));
    let entries = store.entries(&case.id).unwrap();
    assert!(
        !entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
    );
    assert_eq!(engine.pending_approvals(&case.id).unwrap().len(), 1);
    assert_eq!(engine.verify(&case.id).unwrap(), entries.len());
}
