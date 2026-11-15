use super::*;
use irmind_app::MessageRole;
use irmind_app::subagents::{
    SubagentStatus, TaskEvidenceQueries, TaskEvidenceQuery, TaskEvidenceResult,
    VerifiedTaskQueryView,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Queries(AtomicUsize, bool);
impl TaskEvidenceQueries for Queries {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        let text = "Synthetic source-restricted summary.".into();
        Ok(if self.1 {
            TaskEvidenceResult::PartialText {
                text,
                reason: irmind_app::subagents::TaskQueryPartialReason::Sampling,
            }
        } else {
            TaskEvidenceResult::Text(text)
        })
    }
}

struct ParallelModel {
    rounds: std::sync::Mutex<BTreeMap<String, usize>>,
    live: AtomicUsize,
    peak: AtomicUsize,
}
impl ParallelModel {
    fn new() -> Self {
        Self {
            rounds: std::sync::Mutex::new(BTreeMap::new()),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }
}
#[async_trait]
impl LlmPort for ParallelModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let nonce = request.messages[1]
            .content
            .split_once('>')
            .unwrap()
            .0
            .to_owned();
        let round = {
            let mut rounds = self.rounds.lock().unwrap();
            let count = rounds.entry(nonce).or_default();
            *count += 1;
            *count
        };
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(live, Ordering::SeqCst);
        let ready = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None::<std::task::Waker>));
        let signal = ready.clone();
        let wake = waker.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(25));
            signal.store(true, Ordering::SeqCst);
            if let Some(waker) = wake.lock().unwrap().take() {
                waker.wake();
            }
        });
        futures_util::future::poll_fn(|context| {
            *waker.lock().unwrap() = Some(context.waker().clone());
            if ready.load(Ordering::SeqCst) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        worker.join().unwrap();
        self.live.fetch_sub(1, Ordering::SeqCst);
        let calls = if round == 1 {
            vec![
                ModelToolCall::from_proposal(
                    "read_summary",
                    ProposedCall {
                        tool: Tool::GraphSummary,
                        args: BTreeMap::new(),
                    },
                )
                .unwrap(),
            ]
        } else {
            assert!(
                request
                    .messages
                    .iter()
                    .any(|message| message.role == MessageRole::Tool
                        && message.tool_call_id.as_deref() == Some("read_summary")
                        && message.content.contains("<UNTRUSTED_"))
            );
            vec![]
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic delegated review.".into(),
                calls,
                raw: "synthetic".into(),
                truncated: false,
            },
            Some(ModelUsage {
                input_tokens: 5,
                output_tokens: 2,
            }),
        ))
    }
}

#[test]
fn parallel_child_models_overlap_but_signed_checkpoints_and_export_bytes_match_one_worker() {
    check_determinism(false);
    check_determinism(true);
}

fn check_determinism(partial: bool) {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            (0..4).map(|_| proposal(100_000)).collect(),
            SubagentResources::default(),
            &cancel,
        )
        .unwrap();
    let started = engine
        .admit_subagent_plan(
            &prepared,
            &prepared.preview().automatic_start().unwrap(),
            &cancel,
        )
        .unwrap()
        .unwrap();
    let prefix = store.entries(&history.case).unwrap();
    let mut expected = None;
    for workers in [1, 2, 4, 8] {
        let root = tempfile::tempdir().unwrap();
        let mut fork = History::new();
        fork.entries.clone_from(&prefix);
        let queries = Arc::new(Queries(AtomicUsize::new(0), partial));
        let (store, engine) =
            stored_history_engine_with_queries(root.path(), &fork, &[], queries.clone());
        let model = ParallelModel::new();
        let results = engine
            .run_subagent_plan(&started, &model, workers, &cancel)
            .unwrap();
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|result| result.status
            == if partial {
                SubagentStatus::Partial
            } else {
                SubagentStatus::Completed
            }
            && result.usage.calls == 1
            && result.usage.tokens == 14
            && result.usage.rounds == 2));
        assert_eq!(model.peak.load(Ordering::SeqCst), workers.min(4));
        assert_eq!(model.live.load(Ordering::SeqCst), 0);
        assert_eq!(queries.0.load(Ordering::SeqCst), 4);
        engine.finish_subagent_plan(&started).unwrap();
        tools::verify_and_export(store.as_ref(), &engine, &fork, root.path());
        let hashes = store
            .entries(&history.case)
            .unwrap()
            .into_iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>();
        let export = std::fs::read(root.path().join("tool-child.irmind")).unwrap();
        match &expected {
            Some((prior_hashes, prior_export)) => {
                assert_eq!(&hashes, prior_hashes);
                assert_eq!(&export, prior_export);
            }
            None => expected = Some((hashes, export)),
        }
    }
}
