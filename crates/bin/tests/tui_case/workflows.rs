#[cfg(feature = "keystore-file")]
#[test]
#[allow(clippy::too_many_lines)]
fn complete_case_without_os_keyring_from_tui_controller_with_fakes() {
    let root = tempfile::tempdir().unwrap();
    let mut setup_terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let choice = render_keystore_setup(&mut setup_terminal, false).unwrap();
    assert_eq!((choice.signer, choice.secrets), ("file", "file"));
    assert!(screen(&setup_terminal).contains("OS keyring: unavailable"));
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let file_backend = FileKeystore::open(
        root.path(),
        &SecretString::from("synthetic TUI passphrase".to_owned()),
        true,
    )
    .unwrap();
    let signer = file_backend.create(Actor::Analyst).unwrap();
    let intel = FakeIntel;
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
    .unwrap()
    .with_threat_intel(&intel);
    let io_ops = TestIo(store.clone());
    let terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut tui = ScriptedWorkspace::new(terminal, &engine, Some(&model), &io_ops);

    tui.render_home().unwrap();
    assert!(screen(tui.terminal()).contains("IRMind"));
    tui.render_keystore().unwrap();
    assert!(screen(tui.terminal()).contains("Signer: file"));
    let id = tui.create_case("Synthetic incident", Severity::High,
        "v1;sources=siem-a;accounts=acct-a;hosts=;from=2026-10-23T10:00:00Z;to=2026-10-23T11:00:00Z").unwrap();
    tui.render_case(&id, "Case opened").unwrap();
    assert!(screen(tui.terminal()).contains("Synthetic incident"));

    let evidence = root.path().join("synthetic.json");
    std::fs::write(&evidence, br#"{"Records":[{"eventTime":"2026-10-23T10:10:00Z","eventName":"Login","sourceIPAddress":"203.0.113.9"}]}"#).unwrap();
    assert_eq!(tui.ingest_path(&id, &evidence).unwrap(), 1);
    tui.investigate(&id, "Investigate synthetic alert").unwrap();
    let pending = tui.pending_approval_ids(&id).unwrap();
    assert_eq!(pending.len(), 1);
    tui.approve(&id, &pending[0]).unwrap();
    let migration_home = tempfile::tempdir().unwrap();
    let migration_target = MigrationTarget(
        FileKeystore::open(
            migration_home.path(),
            &SecretString::from("second synthetic passphrase".to_owned()),
            true,
        )
        .unwrap(),
    );
    engine
        .migrate_signer_backend(&file_backend, &migration_target)
        .unwrap();
    assert_eq!(
        migration_target
            .public_key_for_actor(&Actor::Analyst)
            .unwrap(),
        signer.public_key()
    );
    file_backend
        .put(
            "SYNTHETIC_API_KEY",
            &SecretString::from("synthetic credential".to_owned()),
        )
        .unwrap();
    engine
        .migrate_secret_backend(&file_backend, &migration_target, &["SYNTHETIC_API_KEY"])
        .unwrap();
    assert_eq!(
        migration_target
            .get("SYNTHETIC_API_KEY")
            .unwrap()
            .expose_secret(),
        "synthetic credential"
    );
    assert!(
        store
            .global_operations()
            .unwrap()
            .iter()
            .any(|entry| entry.operation.contains("keystore-migration:signer"))
    );
    assert!(
        store
            .global_operations()
            .unwrap()
            .iter()
            .any(|entry| entry.operation.contains("keystore-migration:secrets"))
    );
    assert!(store.operations(&id).unwrap().is_empty());
    assert!(tui.verify(&id).unwrap() > 0);
    tui.seal(&id).unwrap();
    let export = root.path().join("synthetic.irmind.json");
    let fingerprint = tui.export(&id, &export).unwrap();
    assert_eq!(fingerprint.len(), 64);
    assert!(export.is_file());
    assert!(
        tui.verify_export(&export, &fingerprint)
            .unwrap()
            .contains("Verified")
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let cancelled_path = root.path().join("cancelled.irmind.json");
    assert!(matches!(
        irmind_app::export_case(&engine, store.as_ref(), &id, &cancelled_path, &cancelled),
        Err(AppError::Cancelled)
    ));
    assert!(!cancelled_path.exists());
    tui.render_case(&id, "Case sealed and exported").unwrap();
    tui.render_home().unwrap();
    assert!(screen(tui.terminal()).contains("sealed"));

    let hash = store.evidence_hashes(&id).unwrap().remove(0);
    std::fs::write(root.path().join("evidence").join(hash), b"tampered").unwrap();
    let rejected_export = root.path().join("must-not-export.irmind.json");
    assert!(tui.export(&id, &rejected_export).is_err());
    assert!(!rejected_export.exists());
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
    let io_ops = TestIo(store);
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
