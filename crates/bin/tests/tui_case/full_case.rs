use super::support::*;
use super::*;

#[cfg(feature = "keystore-file")]
#[test]
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
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
    let io_ops = TestIo(
        store.clone(),
        irmind_infra::TomlConfigurationStore::new(root.path()),
    );
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
    std::fs::write(&evidence, br#"{"Records":[{"eventTime":"2026-10-23T10:10:00Z","eventName":"Login","sourceIPAddress":"203.0.113.9","domain":"example.com"}]}"#).unwrap();
    assert_eq!(tui.ingest_path(&id, &evidence).unwrap(), 1);
    let (_, deltas) = tui
        .investigate_with_deltas(&id, "Investigate synthetic alert")
        .unwrap();
    assert!(deltas.len() >= 2);
    tui.render_model_preview(&id, &deltas[0]).unwrap();
    assert!(screen(tui.terminal()).contains("IRMind (streaming): Synthetic"));
    let pending = tui.pending_approval_ids(&id).unwrap();
    assert_eq!(pending.len(), 1);
    let approval_panel = tui.render_approval_panel(&id).unwrap();
    assert!(approval_panel.contains("[TAINTED]"));
    assert!(approval_panel.contains("example.com"));
    let hash = store.evidence_hashes(&id).unwrap().remove(0);
    let ioc = tui
        .propose_entity(
            &id,
            irmind_app::FindingKind::Ioc,
            "203.0.113.9",
            &hash,
            irmind_app::EntityDetails::Ioc {
                ioc_type: "ip".into(),
                first_seen: "2026-10-23T10:10:00Z".into(),
                last_seen: "2026-10-23T10:10:00Z".into(),
                verdict: "unknown".into(),
            },
        )
        .unwrap();
    let hypothesis = tui
        .propose_entity(
            &id,
            irmind_app::FindingKind::Hypothesis,
            "Suspicious login",
            &hash,
            irmind_app::EntityDetails::Hypothesis {
                supporting_evidence: vec![hash.clone()],
                refuting_evidence: vec![],
            },
        )
        .unwrap();
    let technique = tui
        .propose_entity(
            &id,
            irmind_app::FindingKind::Technique,
            "T1078.004",
            &hash,
            irmind_app::EntityDetails::Technique {
                technique_id: "T1078.004".into(),
            },
        )
        .unwrap();
    assert!(
        tui.render_entity_panel(&id, irmind_app::FindingKind::Ioc)
            .unwrap()
            .contains("proposed")
    );
    assert!(
        tui.render_entity_panel(&id, irmind_app::FindingKind::Hypothesis)
            .unwrap()
            .contains("Suspicious login")
    );
    assert!(
        tui.render_entity_panel(&id, irmind_app::FindingKind::Technique)
            .unwrap()
            .contains("T1078.004")
    );
    tui.confirm_finding(&id, &ioc).unwrap();
    tui.confirm_finding(&id, &hypothesis).unwrap();
    tui.confirm_finding(&id, &technique).unwrap();
    assert!(
        tui.render_entity_panel(&id, irmind_app::FindingKind::Ioc)
            .unwrap()
            .contains("confirmed")
    );
    let report = tui.report(&id).unwrap();
    assert!(report.contains("203.0.113.9"));
    assert!(report.contains(&format!("Suspicious login [supporting evidence: {hash}]")));
    assert!(report.contains(&format!("T1078.004 [evidence: {hash}]")));
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
