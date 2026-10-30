use super::support::*;
use super::*;

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
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let io_ops = TestIo(
        store.clone(),
        irmind_infra::TomlConfigurationStore::new(root.path()),
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
        KeyCode::Enter,
        KeyCode::Down,
        KeyCode::Enter, // Save from review
        KeyCode::Down,
        KeyCode::Enter, // Explicitly approve remote egress
    ]);
    assert!(tui.drive_model_screen(&[module], &keys).unwrap());
    let saved = io_ops.1.load().unwrap();
    assert_eq!(saved.llm_module.as_deref(), Some("llm-openai-compatible"));
    engine
        .verify_configuration(&io_ops.1, &[&irmind_mod_llm_openai_compatible::MANIFEST])
        .unwrap();
    assert!(
        store
            .global_operations()
            .unwrap()
            .iter()
            .any(|entry| entry.operation.starts_with("configuration-approved-v2:"))
    );
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
            Arc::new(JsonParser),
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
            Arc::new(JsonParser),
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
