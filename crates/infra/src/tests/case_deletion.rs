use super::*;
use irmind_app::{CaseDeletedV1, CaseLifecycleError, CaseLifecycleStore};

fn fixture(root: &Path) -> (Arc<LocalStore>, Engine<'static>, CaseId) {
    let (store, engine) = source_fixture(root, 171);
    let engine = engine.with_case_lifecycle(store.clone());
    let case = engine
        .create_case("Synthetic deletion case", "local only")
        .unwrap();
    (store, engine, case.id)
}

#[test]
fn case_deletion_preserves_shared_evidence_and_external_originals() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let original = external.path().join("original.json");
    let bytes = b"synthetic shared content";
    fs::write(&original, bytes).unwrap();
    let (store, engine, id) = fixture(root.path());
    let other = engine
        .create_case("Other synthetic case", "local only")
        .unwrap();
    let hash = hex(&sha256(bytes));
    store.put_evidence(&id, &hash, bytes).unwrap();
    store.put_evidence(&other.id, &hash, bytes).unwrap();
    let owned = store.parquet.case_dir(&id).unwrap();
    for name in ["originals", "spool", "skills", "branches", "catalog-proofs"] {
        fs::create_dir_all(owned.join(name)).unwrap();
        fs::write(owned.join(name).join("synthetic"), b"owned bytes").unwrap();
    }
    let prepared = engine
        .prepare_case_deletion(&id, &CancellationToken::new())
        .unwrap();
    assert_eq!(prepared.inventory().owned_file_bytes, 55);
    assert_eq!(prepared.inventory().shared_blob_bytes, bytes.len() as u64);
    let progress = engine
        .delete_prepared_case(prepared, id.as_str(), Some("synthetic test".into()))
        .unwrap();
    assert!(progress.complete, "{}", progress.message);
    assert!(!owned.exists());
    assert_eq!(fs::read(original).unwrap(), bytes);
    assert_eq!(store.get_evidence(&other.id, &hash).unwrap(), bytes);
    assert_eq!(store.list_cases().unwrap().len(), 1);
    assert!(matches!(
        store.get_case(&id),
        Err(AppError::CaseLifecycle(CaseLifecycleError::Deleted))
    ));
    assert!(store.entries(&id).unwrap().is_empty());
    assert!(store.operations(&id).unwrap().is_empty());
    let receipts = engine.deleted_cases().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].case_id, id.as_str());
    engine.verify_global_operations().unwrap();
    engine.verify(&other.id).unwrap();
    assert!(
        engine
            .resume_case_deletions(&CancellationToken::new())
            .unwrap()[0]
            .complete
    );
    // The last reference is collected, while the global signed tombstones remain.
    let prepared = engine
        .prepare_case_deletion(&other.id, &CancellationToken::new())
        .unwrap();
    assert!(
        engine
            .delete_prepared_case(prepared, other.id.as_str(), None)
            .unwrap()
            .complete
    );
    assert!(!root.path().join("evidence").join(hash).exists());
    assert_eq!(engine.deleted_cases().unwrap().len(), 2);
}

#[test]
fn case_deletion_rejects_wrong_confirmation_sealed_case_and_active_session() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let session = store.open_session(&id).unwrap();
    assert!(matches!(
        engine.prepare_case_deletion(&id, &CancellationToken::new()),
        Err(AppError::CaseLifecycle(CaseLifecycleError::Busy))
    ));
    drop(session);
    let prepared = engine
        .prepare_case_deletion(&id, &CancellationToken::new())
        .unwrap();
    assert!(matches!(
        engine.delete_prepared_case(prepared, "not the title", None),
        Err(AppError::CaseLifecycle(CaseLifecycleError::Confirmation))
    ));
    assert!(store.global_operations().unwrap().is_empty());
    engine.verify(&id).unwrap();
    let seal = engine.prepare_seal(&id).unwrap();
    engine.seal_prepared(&seal).unwrap();
    assert!(matches!(
        engine.prepare_case_deletion(&id, &CancellationToken::new()),
        Err(AppError::Sealed)
    ));
    assert!(store.global_operations().unwrap().is_empty());
}

#[test]
fn case_6_rejects_open_verify_and_deletion_before_reading_later_records() {
    use irmind_app::case_format::{CaseFormatError, FORMAT_GUIDE};

    let root = tempfile::tempdir().unwrap();
    let (store, engine) = source_fixture(root.path(), 171);
    let engine = engine.with_case_lifecycle(store.clone());
    let id = CaseId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
    let key = SigningKey::from_bytes(&[171; 32]);
    let first = SignedEntry {
        seq: 1,
        case_id: id.as_str().to_owned(),
        at: 17,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind: irmind_domain::AuditEventKind::CaseCreated,
        payload: r#"{"version":6,"title":"Synthetic","severity":"medium","scope":"local"}"#.into(),
        evidence: None,
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: key.verifying_key().to_bytes().to_vec(),
    };
    let hash = sha256(&first.canonical());
    let first = SignedEntry {
        hash,
        sig: key.sign(&hash).to_bytes().to_vec(),
        ..first
    };
    store
        .transact(
            &first,
            irmind_app::CaseMutation::Create(Case {
                id: id.clone(),
                title: "Synthetic".into(),
                severity: Severity::Medium,
                scope: "local".into(),
                sealed: false,
            }),
        )
        .unwrap();
    let owned = store.parquet.case_dir(&id).unwrap();
    let bytes = b"synthetic case-owned evidence";
    let source = owned.join("original.json");
    fs::write(&source, bytes).unwrap();
    store.conn().unwrap().execute(
        "INSERT INTO audit (case_id,seq,at,actor,origin,kind,payload,evidence,prev,hash,sig,public_key)
         VALUES (?1,2,17,'analyst','system','intentionally unreadable','',NULL,?2,?2,?3,?4)",
        rusqlite::params![id.as_str(), hash.as_slice(), first.sig, first.public_key],
    ).unwrap();

    let retired = |error: AppError| match error {
        AppError::Fixed(irmind_app::FixedAppError::CaseFormat(CaseFormatError::Case(Some(6)))) => {
            let message = error.to_string();
            assert!(message.contains("v0.7.x"));
            assert!(message.contains("refuses to delete sealed cases"));
            assert!(message.contains(FORMAT_GUIDE));
            true
        }
        _ => false,
    };
    let cancel = CancellationToken::new();
    assert!(engine.open_case_verified(&id, &cancel).is_err_and(retired));
    assert!(engine.verify(&id).is_err_and(retired));
    let export = root.path().join("old.irmind");
    assert!(
        irmind_app::LargeCaseExporter::export_case(
            store.as_ref(),
            &id,
            &export,
            None,
            false,
            &cancel
        )
        .is_err_and(retired)
    );
    assert!(!export.exists());
    assert!(
        engine
            .prepare_case_deletion(&id, &cancel)
            .is_err_and(retired)
    );
    assert_eq!(fs::read(source).unwrap(), bytes);
    assert!(store.global_operations().unwrap().is_empty());
}

#[test]
fn case_deletion_cancelled_before_commit_keeps_case_and_journals() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let token = CancellationToken::new();
    let prepared = engine.prepare_case_deletion(&id, &token).unwrap();
    token.cancel();
    assert!(matches!(
        engine.delete_prepared_case(prepared, id.as_str(), None),
        Err(AppError::Cancelled)
    ));
    assert!(store.global_operations().unwrap().is_empty());
    assert!(store.get_case(&id).is_ok());
    engine.verify(&id).unwrap();
}

#[test]
fn case_deletion_tombstone_matches_approved_canonical_vector() {
    let bytes = include_bytes!("../../../../docs/development/case-deletion-vectors/receipt.json");
    let value: CaseDeletedV1 = serde_json::from_slice(bytes).unwrap();
    assert_eq!(value.canonical().unwrap(), bytes);
    assert_eq!(
        hex(&value.canonical().unwrap()),
        include_str!("../../../../docs/development/case-deletion-vectors/receipt.hex").trim()
    );
    assert_eq!(
        hex(&sha256(bytes)),
        include_str!("../../../../docs/development/case-deletion-vectors/receipt.sha256")
            .split_whitespace()
            .next()
            .unwrap()
    );
    let mut invalid = value.clone();
    invalid.reason = Some("x".repeat(1025));
    assert!(invalid.canonical().is_err());
    invalid = value.clone();
    invalid.deleted_at = 99;
    assert!(invalid.canonical().is_err());
    invalid = value;
    invalid.last_chain_hash = "A".repeat(64);
    assert!(invalid.canonical().is_err());
}

#[test]
fn case_deletion_does_not_disable_append_only_guards() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    engine
        .record_cancellation(&id, irmind_app::CancelledOperation::Verify)
        .unwrap();
    for table in ["audit", "operational_audit"] {
        assert!(
            store
                .conn()
                .unwrap()
                .execute(
                    &format!("DELETE FROM {table} WHERE case_id=?1"),
                    [id.as_str()]
                )
                .is_err()
        );
    }
    engine.verify(&id).unwrap();
}

#[cfg(unix)]
#[test]
fn case_deletion_refuses_symlinks_and_reparse_like_escapes() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("keep"), b"outside").unwrap();
    let (store, engine, id) = fixture(root.path());
    let owned = store.parquet.case_dir(&id).unwrap();
    symlink(outside.path(), owned.join("escape")).unwrap();
    assert!(matches!(
        engine.prepare_case_deletion(&id, &CancellationToken::new()),
        Err(AppError::CaseLifecycle(CaseLifecycleError::UnsafeEntry))
    ));
    assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"outside");
    assert!(store.global_operations().unwrap().is_empty());
}

fn crash_intent(store: &LocalStore, engine: &Engine<'_>, id: &CaseId) -> CaseDeletedV1 {
    let prepared = engine
        .prepare_case_deletion(id, &CancellationToken::new())
        .unwrap();
    let receipt = CaseDeletedV1::new(
        prepared.inventory(),
        Some("crash test".into()),
        prepared.inventory().created_at + 1,
    )
    .unwrap();
    let mut operation = SignedOperation {
        case_id: GLOBAL_OPERATION_SCOPE.into(),
        seq: 1,
        at: receipt.deleted_at,
        actor: Actor::Analyst,
        operation: receipt.payload().unwrap(),
        prev: [0; 32],
        hash: [0; 32],
        sig: vec![],
        public_key: engine.signer.public_key(),
    };
    operation.hash = sha256(&operation.canonical());
    operation.sig = engine.signer.sign(&operation.hash).unwrap();
    // Reproduce a crash after the atomic intent transaction, before any cleanup.
    let mut conn = store.conn().unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute("INSERT INTO global_operational_audit (seq,at,actor,operation,prev,hash,sig,public_key) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![operation.seq,operation.at,"analyst",operation.operation,operation.prev.as_slice(),operation.hash.as_slice(),operation.sig,operation.public_key]).unwrap();
    tx.execute(
        "INSERT INTO case_deletion(case_id,operation_seq,operation) VALUES (?1,?2,?3)",
        params![id.as_str(), operation.seq, operation.operation],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(conn);
    drop(prepared);
    receipt
}

#[test]
fn case_deletion_crash_recovery_authenticates_intent_and_cleans_remaining_files() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let owned = store.parquet.case_dir(&id).unwrap();
    fs::write(owned.join("synthetic"), b"remaining").unwrap();
    let receipt = crash_intent(&store, &engine, &id);
    assert!(store.list_cases().unwrap().is_empty());
    assert!(owned.exists());
    let quarantine = root.path().join("parquet/.deleted");
    fs::create_dir(&quarantine).unwrap();
    fs::rename(&owned, quarantine.join(id.as_str())).unwrap();
    // A second process recreates all leases and authenticates the persisted journal.
    let (reopened, new_engine) = source_fixture(root.path(), 171);
    let new_engine = new_engine.with_case_lifecycle(reopened.clone());
    let recovered = new_engine
        .resume_case_deletions(&CancellationToken::new())
        .unwrap();
    assert!(recovered[0].complete, "{}", recovered[0].message);
    assert!(!quarantine.join(id.as_str()).exists());
    assert!(reopened.entries(&id).unwrap().is_empty());
    assert_eq!(new_engine.deleted_cases().unwrap(), [receipt]);
    assert!(
        reopened
            .conn()
            .unwrap()
            .execute("DELETE FROM global_operational_audit", [])
            .is_err()
    );
}

#[test]
fn case_deletion_unauthenticated_intent_never_authorizes_startup_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let owned = store.parquet.case_dir(&id).unwrap();
    fs::write(owned.join("keep"), b"keep").unwrap();
    crash_intent(&store, &engine, &id);
    store.conn().unwrap().execute_batch("DROP TRIGGER global_operational_audit_no_update; UPDATE global_operational_audit SET sig=zeroblob(64)").unwrap();
    assert!(
        engine
            .resume_case_deletions(&CancellationToken::new())
            .is_err()
    );
    assert!(owned.join("keep").exists());
    assert!(!store.entries(&id).unwrap().is_empty());
}

#[test]
fn case_deletion_cancellation_recovery_is_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let owned = store.parquet.case_dir(&id).unwrap();
    fs::write(owned.join("keep"), b"keep").unwrap();
    crash_intent(&store, &engine, &id);
    let token = CancellationToken::new();
    token.cancel();
    assert!(engine.resume_case_deletions(&token).unwrap().is_empty());
    assert!(owned.join("keep").exists());
    assert!(
        engine
            .resume_case_deletions(&CancellationToken::new())
            .unwrap()[0]
            .complete
    );
    assert!(
        engine
            .resume_case_deletions(&CancellationToken::new())
            .unwrap()[0]
            .complete
    );
    assert_eq!(engine.deleted_cases().unwrap().len(), 1);
}

#[test]
fn case_deletion_session_child() {
    use std::io::{BufRead, Write};
    let Some(root) = std::env::var_os("IRMIND_TEST_DELETION_ROOT") else {
        return;
    };
    let id = CaseId::parse(&std::env::var("IRMIND_TEST_DELETION_ID").unwrap()).unwrap();
    let store = open_source_store(Path::new(&root)).unwrap();
    let _session = store.open_session(&id).unwrap();
    println!("DELETION_SESSION_HELD");
    std::io::stdout().flush().unwrap();
    let mut release = String::new();
    std::io::stdin().lock().read_line(&mut release).unwrap();
    assert_eq!(release.trim(), "release");
}

#[test]
fn case_deletion_native_process_session_prevents_removal() {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::case_deletion::case_deletion_session_child",
            "--nocapture",
        ])
        .env("IRMIND_TEST_DELETION_ROOT", root.path())
        .env("IRMIND_TEST_DELETION_ID", id.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(output)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("DELETION_SESSION_HELD") {
                let _ = tx.send(());
            }
        }
    });
    if rx.recv_timeout(std::time::Duration::from_secs(10)).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child did not acquire session lease");
    }
    assert!(matches!(
        engine.prepare_case_deletion(&id, &CancellationToken::new()),
        Err(AppError::CaseLifecycle(CaseLifecycleError::Busy))
    ));
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(store.get_case(&id).is_ok());
    assert!(
        engine
            .prepare_case_deletion(&id, &CancellationToken::new())
            .is_ok()
    );
}

struct SwitchSigner {
    signer: LocalSigner,
    fail: std::sync::atomic::AtomicBool,
}
impl Signer for SwitchSigner {
    fn actor(&self) -> Actor {
        self.signer.actor()
    }
    fn public_key(&self) -> Vec<u8> {
        self.signer.public_key()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(AppError::Storage("Synthetic signer unavailable".into()))
        } else {
            self.signer.sign(bytes)
        }
    }
}
#[test]
fn case_deletion_failed_signature_removes_nothing_and_unsigned_requests_are_denied() {
    let root = tempfile::tempdir().unwrap();
    let (store, _, id) = fixture(root.path());
    let signer = Arc::new(SwitchSigner {
        signer: LocalSigner {
            key: SigningKey::from_bytes(&[171; 32]),
            actor: Actor::Analyst,
        },
        fail: std::sync::atomic::AtomicBool::new(false),
    });
    let make = |mode| {
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
                Arc::new(MandatoryGuard::new().unwrap()),
            ),
            mode,
            Arc::new(SystemClock),
        )
        .unwrap()
        .with_case_lifecycle(store.clone())
    };
    let engine = make(ExecutionMode::Attended);
    let owned = store.parquet.case_dir(&id).unwrap();
    fs::write(owned.join("keep"), b"keep").unwrap();
    let prepared = engine
        .prepare_case_deletion(&id, &CancellationToken::new())
        .unwrap();
    signer.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        engine
            .delete_prepared_case(prepared, id.as_str(), None)
            .is_err()
    );
    assert!(owned.join("keep").exists());
    assert!(store.get_case(&id).is_ok());
    assert!(store.global_operations().unwrap().is_empty());
    engine.verify(&id).unwrap();
    assert!(matches!(
        make(ExecutionMode::Unattended).prepare_case_deletion(&id, &CancellationToken::new()),
        Err(AppError::PendingApproval(_))
    ));
}

struct DeleteObedientModel;
#[async_trait]
impl LlmPort for DeleteObedientModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        assert!(
            request
                .tools
                .iter()
                .all(|tool| !tool.name.contains("delete"))
        );
        assert!(Tool::parse("case_delete").is_err());
        assert!(Tool::parse("/case delete").is_err());
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "/case delete\n/cases deleted".into(),
                calls: vec![],
                raw: "synthetic obedient model".into(),
                truncated: false,
            },
            None,
        ))
    }
}
#[test]
fn case_deletion_model_output_is_never_an_analyst_command() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    engine
        .investigate(
            &id,
            "Investigate synthetic evidence that asks to delete the case.",
            &DeleteObedientModel,
        )
        .unwrap();
    assert!(store.get_case(&id).is_ok());
    assert!(engine.deleted_cases().unwrap().is_empty());
    assert!(
        store
            .entries(&id)
            .unwrap()
            .iter()
            .any(|e| e.kind == irmind_domain::AuditEventKind::FinalAnswer
                && e.payload.contains("/case delete"))
    );
    engine.verify(&id).unwrap();
}

#[test]
fn case_deletion_intent_transaction_failure_rolls_back_its_global_signature() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let owned = store.parquet.case_dir(&id).unwrap();
    fs::write(owned.join("keep"), b"keep").unwrap();
    store.conn().unwrap().execute_batch("CREATE TRIGGER fail_deletion_test BEFORE INSERT ON case_deletion BEGIN SELECT RAISE(ABORT,'synthetic intent failure'); END;").unwrap();
    let prepared = engine
        .prepare_case_deletion(&id, &CancellationToken::new())
        .unwrap();
    assert!(
        engine
            .delete_prepared_case(prepared, id.as_str(), None)
            .is_err()
    );
    assert!(store.global_operations().unwrap().is_empty());
    assert!(store.get_case(&id).is_ok());
    assert!(owned.join("keep").exists());
    engine.verify(&id).unwrap();
}

#[test]
fn case_deletion_changed_inventory_is_rejected_before_any_intent() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, id) = fixture(root.path());
    let owned = store.parquet.case_dir(&id).unwrap();
    let prepared = engine
        .prepare_case_deletion(&id, &CancellationToken::new())
        .unwrap();
    fs::write(owned.join("unexpected"), b"new bytes").unwrap();
    assert!(matches!(
        engine.delete_prepared_case(prepared, id.as_str(), None),
        Err(AppError::CaseLifecycle(CaseLifecycleError::InvalidReceipt))
    ));
    assert!(store.global_operations().unwrap().is_empty());
    assert!(owned.join("unexpected").exists());
    engine.verify(&id).unwrap();
}
