use super::support::*;
use super::*;
use irmind_app::ingest_outcome::{FileFingerprint, FileIdentity, FileReason, IngestFileOutcome};

#[test]
#[allow(clippy::too_many_lines)]
fn tui_selects_fake_llm_and_completes_question_without_process_restart() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[119u8; 32])));
    let model = FakeModel(AtomicUsize::new(0));
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
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let io_ops = TestIo(
        store.clone(),
        irmind_infra::TomlConfigurationStore::new(root.path()),
        None,
    );
    let terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut tui = ScriptedWorkspace::new(terminal, &engine, None, &io_ops);
    let module = ModuleStatus {
        id: "llm-openai-compatible".into(),
        compiled: true,
        enabled: false,
        configuration: "disabled".into(),
        kind: ModuleKind::Llm,
        selected: false,
        selection_source: ModuleSelectionSource::Persistent,
        parameters: vec![ModuleParameter {
            name: "IRMIND_MODEL".into(),
            value: String::new(),
            defaulted: false,
            required: true,
            overridden: false,
        }],
        credentials: Vec::new(),
        missing: Vec::new(),
    };
    let mut keys = vec![
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Enter, // OpenAI preset
        KeyCode::Enter, // Accept the default URL
    ];
    keys.extend("synthetic-key".chars().map(KeyCode::Char));
    keys.extend([KeyCode::Enter, KeyCode::Enter]); // Skip model listing after confirmation
    keys.extend("synthetic-model".chars().map(KeyCode::Char));
    keys.extend([
        KeyCode::Enter, // Model name
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Enter, // Native output maximum
    ]);
    keys.extend("128000".chars().map(KeyCode::Char));
    keys.extend([
        KeyCode::Enter,
        KeyCode::Down, // Parameter required
        KeyCode::Enter,
        KeyCode::Up,
        KeyCode::Up, // Save from review
        KeyCode::Enter,
        KeyCode::Down,
        KeyCode::Enter, // Explicitly approve remote egress
    ]);
    assert!(tui.drive_model_screen(&[module], &keys).unwrap());
    let saved = io_ops.1.load().unwrap();
    assert_eq!(saved.llm_module.as_deref(), Some("llm-openai-compatible"));
    engine
        .verify_configuration(&io_ops.1, &[&irmind_mod_llm_openai_compatible::MANIFEST])
        .unwrap();
    let operations = store.global_operations().unwrap();
    assert_eq!(
        operations.len(),
        1,
        "the complete draft must be signed once"
    );
    assert_eq!(operations[0].actor, Actor::Analyst);
    assert!(
        operations[0]
            .operation
            .starts_with("configuration-approved-v2:")
    );
    let settings = &saved.modules["llm-openai-compatible"].values;
    assert_eq!(
        settings["IRMIND_LLM_BASE_URL"],
        "https://api.openai.com/v1/"
    );
    assert_eq!(settings["IRMIND_MODEL"], "synthetic-model");
    assert_eq!(settings["IRMIND_MODEL_MAX_OUTPUT_TOKENS"], "128000");
    assert_eq!(settings["IRMIND_MODEL_OUTPUT_REQUIRED"], "true");
    assert!(screen(tui.terminal()).contains("Model setup"));

    tui.select_model(&model);
    let id = tui
        .create_case("Synthetic TUI model", Severity::Low, "local evidence only")
        .unwrap();
    tui.investigate(&id, "Explain the synthetic alert").unwrap();
    assert_eq!(model.0.load(Ordering::SeqCst), 2);
    assert_eq!(tui.pending_approval_ids(&id).unwrap().len(), 1);
    std::fs::write(root.path().join("config.toml"), "version = 1\n").unwrap();
    assert!(matches!(
        engine.verify_configuration(&io_ops.1, &[&irmind_mod_llm_openai_compatible::MANIFEST]),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyConfigurationAuditMismatch
        ))
    ));
}

#[cfg(feature = "keystore-file")]
#[test]
fn keystore_migration_without_a_case_is_globally_signed() {
    let root = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let source = FileKeystore::open(
        root.path(),
        &SecretString::from("synthetic source passphrase".to_owned()),
        true,
    )
    .unwrap();
    let target = MigrationTarget(
        FileKeystore::open(
            target_root.path(),
            &SecretString::from("synthetic target passphrase".to_owned()),
            true,
        )
        .unwrap(),
    );
    let signer = source.create(Actor::Analyst).unwrap();
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
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    source
        .put(
            "SYNTHETIC_API_KEY",
            &SecretString::from("fictional secret".to_owned()),
        )
        .unwrap();
    assert!(store.list_cases().unwrap().is_empty());
    engine.migrate_signer_backend(&source, &target).unwrap();
    engine
        .migrate_secret_backend(&source, &target, &["SYNTHETIC_API_KEY"])
        .unwrap();
    let operations = store.global_operations().unwrap();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0].case_id, irmind_app::GLOBAL_OPERATION_SCOPE);
    assert_eq!(operations[1].prev, operations[0].hash);
    assert_eq!(
        target.public_key_for_actor(&Actor::Analyst).unwrap(),
        signer.public_key()
    );
    engine.verify_global_operations().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn tui_renders_while_a_local_port_is_slow() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let slow_repo = Arc::new(SlowRepository {
        store: store.clone(),
        delay_next_read: AtomicBool::new(false),
    });
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[120u8; 32])));
    let intel = FakeIntel;
    let model = FakeModel(AtomicUsize::new(0));
    let engine = Engine::new(
        EnginePorts::new(
            slow_repo.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_threat_intel(&intel);
    let id = engine
        .create_case_with_severity("Synthetic slow port", Severity::Low, "local-only")
        .unwrap()
        .id;
    let io_ops = TestIo(
        store,
        irmind_infra::TomlConfigurationStore::new(root.path()),
        None,
    );
    let terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let mut tui = ScriptedWorkspace::new(terminal, &engine, Some(&model), &io_ops);
    slow_repo.delay_next_read.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let cancel = CancellationToken::new();
    let (investigation, tick) = tokio::join!(
        engine.investigate_cancelable(&id, "Synthetic alert", &model, &cancel),
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tui.render_home().unwrap();
            assert!(screen(tui.terminal()).contains("IRMind"));
            started.elapsed()
        }
    );
    assert!(investigation.is_ok());
    assert!(
        tick < Duration::from_secs(1),
        "TUI render tick was blocked by local I/O"
    );
}

#[test]
fn signed_mapped_rebuild_does_not_require_a_format_detector_for_its_decoder() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(current_sources::open(root.path()));
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[118u8; 32])));
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
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let mut io_ops = TestIo(
        store,
        irmind_infra::TomlConfigurationStore::new(root.path()),
        None,
    );
    let terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    let tui = ScriptedWorkspace::new(terminal, &engine, None, &io_ops);
    let id = tui
        .create_case("Identified source", Severity::Medium, "local only")
        .unwrap();
    let source = root.path().join("synthetic.json");
    std::fs::write(
        &source,
        br#"{"eventTime":"2026-10-23T10:10:00Z","eventName":"SyntheticLogin"}"#,
    )
    .unwrap();
    assert_eq!(tui.ingest_path(&id, &source).unwrap(), 1);
    drop(tui);
    // Connector decoders belong to the signed mapping catalog, not automatic file detection.
    io_ops.2 = Some(irmind_app::modules::ParserCatalog::default());
    let terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    let tui = ScriptedWorkspace::new(terminal, &engine, None, &io_ops);
    assert_eq!(
        tui.verify_graph_with_source_root(&id, root.path()).unwrap(),
        1
    );
    std::fs::write(&source, b"changed").unwrap();
    assert!(tui.verify_graph_with_source_root(&id, root.path()).is_err());
}

#[test]
fn evidence_questions_read_the_case_even_when_the_model_refuses() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(current_sources::open(root.path()));
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[117; 32])));
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
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let io = TestIo(
        store.clone(),
        irmind_infra::TomlConfigurationStore::new(root.path()),
        None,
    );
    let model = RefusingModel(AtomicUsize::new(0));
    let terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    let tui = ScriptedWorkspace::new(terminal, &engine, Some(&model), &io);
    let id = tui
        .create_case("Synthetic evidence", Severity::Low, "local only")
        .unwrap();
    let source = root.path().join("synthetic.json");
    std::fs::write(
        &source,
        br#"{"eventTime":"2026-10-23T10:10:00Z","eventName":"SyntheticLogin"}"#,
    )
    .unwrap();
    assert_eq!(tui.ingest_path(&id, &source).unwrap(), 1);
    let identity = FileIdentity::Complete(FileFingerprint {
        size: 12,
        sha256: [2; 32],
    });
    engine
        .record_ingest_outcomes(
            &id,
            &[
                IngestFileOutcome::Disposition {
                    path: "unrecognized.bin".into(),
                    identity,
                    reason: FileReason::AnalystSkipped,
                },
                IngestFileOutcome::Disposition {
                    path: "damaged.json.gz".into(),
                    identity,
                    reason: FileReason::InvalidFormat,
                },
            ],
            &CancellationToken::new(),
        )
        .unwrap();
    let before = store.entries(&id).unwrap().len();
    for question in [
        "/evidence",
        "¿Qué hemos ingerido?",
        "What have we ingested?",
    ] {
        let status = tui.investigate(&id, question).unwrap();
        assert!(status.contains("synthetic.json"));
        assert!(status.contains("Parquet records=1"));
        assert!(status.contains("1 skipped · 1 failed"));
        assert!(status.contains("unrecognized.bin"));
        assert!(status.contains("damaged.json.gz"));
        assert!(status.contains("2026-10-23T10:10:00"));
    }
    assert_eq!(store.entries(&id).unwrap().len(), before);
    assert_eq!(model.0.load(Ordering::SeqCst), 0);
}

struct RefusingModel(AtomicUsize);

#[irmind_app::async_trait]
impl LlmPort for RefusingModel {
    async fn complete(
        &self,
        _request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(AppError::Model("I refuse to discuss the case".into()))
    }
}
