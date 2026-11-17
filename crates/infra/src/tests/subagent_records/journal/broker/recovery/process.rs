//! Real process boundaries: an event signals ownership; elapsed time never proves it.
use super::*;
use irmind_app::{
    CaseLifecycleStore,
    subagents::{
        BoundedBranchBytes, BranchChunkRef, CheckedBranchChunk, PublishedBranchChunk,
        StagedBranchChunk, SubagentBranchStore,
    },
};
use std::{
    io::{BufRead as _, Write as _},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

const WORKER: &str =
    "tests::subagent_records::journal::broker::recovery::process::plan_process_worker";
struct Worker {
    process: Child,
    events: mpsc::Receiver<String>,
}
impl Worker {
    fn start(root: &Path, mode: &str) -> Self {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", WORKER, "--nocapture"])
            .env("IRMIND_TEST_PLAN_ROOT", root)
            .env("IRMIND_TEST_PLAN_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = process.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let mut worker = Self { process, events };
        worker.wait("PLAN_READY");
        worker
    }
    fn wait(&mut self, expected: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let line = self
                .events
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .unwrap_or_else(|_| panic!("process failed to signal the bounded test event"));
            if line.contains(expected) {
                return;
            }
        }
    }
    fn release(&mut self) {
        writeln!(self.process.stdin.as_mut().unwrap(), "release").unwrap();
        self.wait("PLAN_DONE");
        assert!(self.process.wait().unwrap().success());
    }
    fn kill(&mut self) {
        self.process.kill().unwrap();
        self.process.wait().unwrap();
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
fn signal(text: &str) {
    println!("{text}");
    std::io::stdout().flush().unwrap();
}
fn wait_release() {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "release");
}
fn reopen(root: &Path) -> (Arc<LocalStore>, Engine<'static>) {
    let history = History::new();
    let store = Arc::new(open_source_store(root).unwrap());
    let (store, engine) = configured_history_engine(
        root,
        &history,
        store,
        Arc::new(NoTaskQueries),
        Arc::new(NoPlanInteraction),
    );
    let engine = engine.with_case_lifecycle(store.clone());
    (store, engine)
}
struct HeldModel;
#[async_trait]
impl LlmPort for HeldModel {
    fn output_profile(&self) -> irmind_app::ModelOutputProfile {
        irmind_app::ModelOutputProfile::known(2048, false).unwrap()
    }
    async fn complete(
        &self,
        _: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        signal("PLAN_READY");
        wait_release();
        Err(AppError::Cancelled)
    }
}
#[test]
fn plan_process_worker() {
    let Some(root) = std::env::var_os("IRMIND_TEST_PLAN_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let mode = std::env::var("IRMIND_TEST_PLAN_MODE").unwrap();
    let history = History::new();
    let (store, engine) = reopen(&root);
    if mode == "detached" {
        detached_worker(&root, &history, store.clone());
        return;
    }
    if mode == "recovery" {
        recover_worker(&root, &history, store.clone());
        return;
    }
    if mode == "exclusive" {
        let gate = store.parquet.try_plan_recovery(&history.case).unwrap();
        signal("PLAN_READY");
        wait_release();
        drop(gate);
        signal("PLAN_DONE");
        return;
    }
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(100_000)],
            SubagentResources::default(),
            &CancellationToken::new(),
        )
        .unwrap();
    if mode == "preview" {
        signal("PLAN_READY");
        wait_release();
        drop(prepared);
        signal("PLAN_DONE");
        return;
    }
    let started = Arc::new(
        engine
            .admit_subagent_plan(
                &prepared,
                &prepared.preview().automatic_start().unwrap(),
                &CancellationToken::new(),
            )
            .unwrap()
            .unwrap(),
    );
    let worker_started = started.clone();
    drop(started);
    drop(prepared);
    let worker = std::thread::spawn(move || {
        let _ = engine.run_subagent_task(
            &worker_started,
            worker_started.plan().tasks[0].task_id,
            &HeldModel,
            &CancellationToken::new(),
        );
        engine.finish_subagent_plan(&worker_started).unwrap();
    });
    worker.join().unwrap();
    signal("PLAN_DONE");
}
#[test]
fn other_process_preview_and_running_child_block_recovery_and_deletion_until_exit() {
    for mode in ["preview", "running", "detached"] {
        let root = tempfile::tempdir().unwrap();
        let history = History::new();
        let (store, engine) = stored_history_engine(root.path(), &history, &[]);
        let engine = engine.with_case_lifecycle(store.clone());
        let mut worker = Worker::start(root.path(), mode);
        let before = store.entries(&history.case).unwrap();
        assert!(
            engine
                .cancel_interrupted_subagent_plans(&history.case)
                .unwrap_err()
                .to_string()
                .contains("another session")
        );
        assert_eq!(
            store.entries(&history.case).unwrap().last().unwrap().hash,
            before.last().unwrap().hash
        );
        assert!(
            store
                .prepare_deletion(&history.case, &CancellationToken::new())
                .is_err()
        );
        // Ordinary reads and an independent short repository transaction remain usable.
        engine.verify(&history.case).unwrap();
        drop(store.lock_case(&history.case).unwrap());
        worker.kill();
        assert_eq!(
            engine
                .cancel_interrupted_subagent_plans(&history.case)
                .unwrap(),
            1
        );
        assert_eq!(
            engine
                .cancel_interrupted_subagent_plans(&history.case)
                .unwrap(),
            0
        );
        if mode != "preview" {
            let mut journal =
                SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
            for entry in store.entries(&history.case).unwrap() {
                journal.accept(&entry, &history.verifier).unwrap();
            }
            if mode == "running" {
                assert!(journal.outstanding().unwrap().tokens > 0);
            } else {
                let usage =
                    irmind_app::case_budget_usage(&store.entries(&history.case).unwrap()).unwrap();
                assert_eq!(usage.model_tokens, 7);
                assert_eq!(usage.tool_calls, 1);
            }
        }
        tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
    }
}
#[test]
fn other_process_exclusive_gate_prevents_holds_and_concurrent_recovery() {
    let root = tempfile::tempdir().unwrap();
    let history = History::new();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let mut worker = Worker::start(root.path(), "exclusive");
    let before = store.entries(&history.case).unwrap().len();
    assert!(
        engine
            .prepare_subagent_plan(
                &history.case,
                "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                vec![proposal(100_000)],
                SubagentResources::default(),
                &CancellationToken::new()
            )
            .is_err()
    );
    assert!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .is_err()
    );
    assert_eq!(store.entries(&history.case).unwrap().len(), before);
    worker.release();
    assert_eq!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .unwrap(),
        0
    );
}

fn recover_worker(root: &Path, history: &History, store: Arc<LocalStore>) {
    let (_, engine) = configured_history_engine_with_branches(
        root,
        history,
        store.clone(),
        Arc::new(NoTaskQueries),
        Arc::new(NoPlanInteraction),
        Arc::new(ReadBarrier {
            inner: ParquetStore::open(root).unwrap(),
            waited: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let engine = engine.with_case_lifecycle(store);
    assert_eq!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .unwrap(),
        1
    );
    signal("PLAN_DONE");
}

struct ReadBarrier {
    inner: ParquetStore,
    waited: std::sync::atomic::AtomicBool,
}
impl SubagentBranchStore for ReadBarrier {
    fn try_plan_activity(&self, case: &CaseId) -> Result<Box<dyn irmind_app::CaseLock>, AppError> {
        self.inner.try_plan_activity(case)
    }
    fn try_plan_recovery(&self, case: &CaseId) -> Result<Box<dyn irmind_app::CaseLock>, AppError> {
        self.inner.try_plan_recovery(case)
    }
    fn stage(
        &self,
        case: &CaseId,
        chunk: &CheckedBranchChunk,
        cancel: &CancellationToken,
    ) -> Result<StagedBranchChunk, AppError> {
        self.inner.stage(case, chunk, cancel)
    }
    fn publish(&self, staged: StagedBranchChunk) -> Result<PublishedBranchChunk, AppError> {
        self.inner.publish(staged)
    }
    fn discard(&self, staged: StagedBranchChunk) -> Result<(), AppError> {
        self.inner.discard(staged)
    }
    fn read(
        &self,
        case: &CaseId,
        reference: &BranchChunkRef,
        cancel: &CancellationToken,
    ) -> Result<BoundedBranchBytes, AppError> {
        if !self.waited.swap(true, std::sync::atomic::Ordering::SeqCst) {
            signal("PLAN_READY");
            wait_release();
        }
        self.inner.read(case, reference, cancel)
    }
}
#[test]
fn engine_retains_exclusive_lease_through_material_verification_and_reconciliation() {
    let root = tempfile::tempdir().unwrap();
    let history = History::new();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let mut live = Worker::start(root.path(), "running");
    live.kill();
    let before = store.entries(&history.case).unwrap().last().unwrap().hash;
    let mut recovery = Worker::start(root.path(), "recovery");
    assert!(
        engine
            .prepare_subagent_plan(
                &history.case,
                "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                vec![proposal(100_000)],
                SubagentResources::default(),
                &CancellationToken::new()
            )
            .is_err()
    );
    assert!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .is_err()
    );
    assert!(
        store
            .prepare_deletion(&history.case, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(
        store.entries(&history.case).unwrap().last().unwrap().hash,
        before
    );
    recovery.release();
    assert_eq!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .unwrap(),
        0
    );
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}

struct Uncoordinated;
impl SubagentBranchStore for Uncoordinated {
    fn stage(
        &self,
        _: &CaseId,
        _: &CheckedBranchChunk,
        _: &CancellationToken,
    ) -> Result<StagedBranchChunk, AppError> {
        panic!("coordination must fail before staging")
    }
    fn publish(&self, _: StagedBranchChunk) -> Result<PublishedBranchChunk, AppError> {
        panic!("coordination must fail before publishing")
    }
    fn discard(&self, _: StagedBranchChunk) -> Result<(), AppError> {
        panic!("coordination must fail before discarding")
    }
    fn read(
        &self,
        _: &CaseId,
        _: &BranchChunkRef,
        _: &CancellationToken,
    ) -> Result<BoundedBranchBytes, AppError> {
        panic!("coordination must fail before reading")
    }
}
#[test]
fn unavailable_coordination_and_lock_errors_never_publish_holds_or_recovery() {
    let root = tempfile::tempdir().unwrap();
    let history = History::new();
    let (store, _) = stored_history_engine(root.path(), &history, &[]);
    let (_, engine) = configured_history_engine_with_branches(
        root.path(),
        &history,
        store.clone(),
        Arc::new(NoTaskQueries),
        Arc::new(NoPlanInteraction),
        Arc::new(Uncoordinated),
    );
    let before = store.entries(&history.case).unwrap().len();
    let prepare = || {
        engine.prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![proposal(100_000)],
            SubagentResources::default(),
            &CancellationToken::new(),
        )
    };
    assert!(prepare().err().unwrap().to_string().contains("unavailable"));
    assert!(
        engine
            .cancel_interrupted_subagent_plans(&history.case)
            .unwrap_err()
            .to_string()
            .contains("unavailable")
    );
    assert_eq!(store.entries(&history.case).unwrap().len(), before);
    let gate = root
        .path()
        .join("locks")
        .join(format!("{}.subagent-plan", history.case.as_str()));
    fs::create_dir(&gate).unwrap();
    let branches = ParquetStore::open(root.path()).unwrap();
    assert!(branches.try_plan_activity(&history.case).is_err());
    assert!(branches.try_plan_recovery(&history.case).is_err());
    assert!(Tool::parse("subagents_recover").is_err());
    assert!(
        irmind_app::tool_catalog::catalog()
            .iter()
            .all(|tool| !tool.name.contains("recover"))
    );
}

struct HeldQueries {
    entered: mpsc::SyncSender<()>,
    release: std::sync::Mutex<mpsc::Receiver<()>>,
}
impl irmind_app::subagents::TaskEvidenceQueries for HeldQueries {
    fn execute(
        &self,
        view: &irmind_app::subagents::VerifiedTaskQueryView,
        query: irmind_app::subagents::TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<irmind_app::subagents::TaskEvidenceResult, AppError> {
        query.validate(view)?;
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        Ok(irmind_app::subagents::TaskEvidenceResult::Text(
            "Synthetic finished callback".into(),
        ))
    }
}
fn detached_worker(root: &Path, history: &History, store: Arc<LocalStore>) {
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let queries = Arc::new(HeldQueries {
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let (_, engine) = configured_history_engine(
        root,
        history,
        store.clone(),
        queries,
        Arc::new(NoPlanInteraction),
    );
    let engine = engine.with_case_lifecycle(store);
    let started = tools::start(&engine, history);
    let (abort, registration) = futures_util::future::AbortHandle::new_pair();
    let (aborted_tx, aborted_rx) = mpsc::sync_channel(1);
    let driver = std::thread::spawn(move || {
        irmind_testkit::run_test_future(async move {
            let child = futures_util::future::Abortable::new(
                async move {
                    let model = tools::ToolModel {
                        requests: std::sync::Mutex::default(),
                        repeat: false,
                        tool: Tool::GraphSummary,
                    };
                    engine
                        .execute_subagent_task(
                            &started,
                            started.plan().tasks[0].task_id,
                            &model,
                            &CancellationToken::new(),
                        )
                        .await
                },
                registration,
            );
            assert!(child.await.is_err());
            aborted_tx.send(()).unwrap();
        })
        .unwrap();
    });
    entered_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    abort.abort();
    aborted_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    // All root/prepared/started handles are gone; only the callback retains activity.
    signal("PLAN_READY");
    wait_release();
    release_tx.send(()).unwrap();
    driver.join().unwrap();
    signal("PLAN_DONE");
}
