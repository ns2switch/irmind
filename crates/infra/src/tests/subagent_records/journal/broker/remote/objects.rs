use super::*;
use irmind_app::{ObjectEntry, ObjectSource, ObjectSourceOutput};
use irmind_domain::UtcTimestamp;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Automatic,
    Approve,
    Deny,
    NoListing,
    ChangedVersion,
    Cancel,
    OverBudget,
}
struct Objects {
    mode: Mode,
    reads: AtomicUsize,
}
fn object() -> ObjectEntry {
    ObjectEntry {
        uri: "s3://synthetic-bucket/logs/cloud.json".into(),
        key: "logs/cloud.json".into(),
        size: RESPONSE.len() as u64,
        modified_unix_seconds: Some(
            u64::try_from(
                UtcTimestamp::parse("2026-11-01T00:00:00Z")
                    .unwrap()
                    .unix_seconds(),
            )
            .unwrap(),
        ),
        version: Some("synthetic-version".into()),
        provider_checksum: Some("etag:synthetic-etag".into()),
    }
}
#[async_trait]
impl ObjectSource for Objects {
    fn source_id(&self) -> &'static str {
        "storage-test"
    }
    async fn execute(
        &self,
        call: &irmind_domain::AuthorizedCall,
        _: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError> {
        match call.tool() {
            Tool::ObjectList => Ok(ObjectSourceOutput::Listing {
                objects: vec![object()],
                total_bytes: RESPONSE.len() as u64,
                truncated: false,
            }),
            Tool::ObjectRead => {
                self.reads.fetch_add(1, Ordering::SeqCst);
                let mut metadata = object();
                if matches!(self.mode, Mode::ChangedVersion) {
                    metadata.version = Some("unexpected-version".into());
                }
                let chunks = if matches!(self.mode, Mode::Cancel) {
                    use futures_util::StreamExt as _;
                    futures_util::stream::pending::<Result<Vec<u8>, AppError>>().boxed()
                } else {
                    use futures_util::StreamExt as _;
                    futures_util::stream::iter([Ok(RESPONSE.to_vec())]).boxed()
                };
                Ok(ObjectSourceOutput::Object { metadata, chunks })
            }
            _ => Err(AppError::RemoteTool),
        }
    }
}
struct ObjectModel {
    mode: Mode,
}
#[async_trait]
impl LlmPort for ObjectModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let called = |id| {
            request
                .messages
                .iter()
                .any(|message| message.tool_call_id.as_deref() == Some(id))
        };
        let base = || {
            BTreeMap::from([
                ("source".into(), "storage-test".into()),
                ("scheme".into(), "s3".into()),
                ("container".into(), "synthetic-bucket".into()),
                ("from".into(), "2026-11-01T00:00:00Z".into()),
                ("to".into(), "2026-11-01T23:59:59Z".into()),
            ])
        };
        let call = if !called("listing") && !matches!(self.mode, Mode::NoListing) {
            let mut args = base();
            args.insert("prefix".into(), "logs/".into());
            args.insert("limit".into(), "10".into());
            Some(("listing", Tool::ObjectList, args))
        } else if !called("download") {
            let mut args = base();
            args.insert("key".into(), object().key);
            args.insert("version".into(), "synthetic-version".into());
            args.insert("max_bytes".into(), RESPONSE.len().to_string());
            args.insert("copy_original".into(), "false".into());
            Some(("download", Tool::ObjectRead, args))
        } else if !called("summary") {
            Some(("summary", Tool::GraphSummary, BTreeMap::new()))
        } else {
            None
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic versioned object review".into(),
                calls: call
                    .map(|(id, tool, args)| {
                        ModelToolCall::from_proposal(id, ProposedCall { tool, args }).unwrap()
                    })
                    .into_iter()
                    .collect(),
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
fn child_object_reads_reserve_bytes_require_own_listing_and_clean_the_case_spool() {
    for mode in [
        Mode::Automatic,
        Mode::Approve,
        Mode::Deny,
        Mode::NoListing,
        Mode::ChangedVersion,
        Mode::Cancel,
        Mode::OverBudget,
    ] {
        scenario(mode);
    }
}
fn scenario(mode: Mode) {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let views = Arc::new(Views(Mutex::default()));
    let (store, mut engine) =
        stored_history_engine_with_queries(root.path(), &history, &[], views.clone());
    let objects = Objects {
        mode,
        reads: AtomicUsize::new(0),
    };
    engine.policy.object_transfer_approval_bytes = if matches!(mode, Mode::Approve | Mode::Deny) {
        1
    } else {
        1_000_000
    };
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(JsonParser), &ModuleConfig::new())
        .unwrap();
    let engine = engine
        .with_object_source(&objects)
        .unwrap()
        .with_large_case_pipeline(
            Arc::new(ParquetStore::open_mapped(root.path(), source_mapping_catalog()).unwrap()),
            Arc::new(json_source_parser()),
        )
        .with_parser_catalog(registry.parser_catalog());
    let scope = "v3;sources=storage-test;accounts=;projects=;hosts=;objects=s3://synthetic-bucket/logs/;from=2026-11-01T00:00:00Z;to=2026-11-01T23:59:59Z";
    engine.change_scope(&history.case, scope).unwrap();
    if matches!(mode, Mode::NoListing) {
        parent_listing(&engine, &history.case);
    }
    let cancel = CancellationToken::new();
    let started = start_object_plan(&engine, &history.case, scope, mode, &cancel);
    let task = started.plan().tasks[0].task_id;
    let analyst = &engine;
    let case = history.case.clone();
    let observed = &objects;
    let result = std::thread::scope(|threads| {
        let control = threads.spawn(move || control_task(analyst, observed, &case, task, mode));
        let result = engine
            .run_subagent_plan(&started, &ObjectModel { mode }, 1, &cancel)
            .unwrap();
        control.join().unwrap();
        result
    });
    let downloaded = !matches!(mode, Mode::Deny | Mode::NoListing | Mode::OverBudget);
    assert_eq!(
        objects.reads.load(Ordering::SeqCst),
        usize::from(downloaded),
        "{mode:?}: {result:?}"
    );
    let ingested = matches!(mode, Mode::Automatic | Mode::Approve);
    assert_eq!(
        result[0].usage.cloud_bytes,
        if downloaded { RESPONSE.len() as u64 } else { 0 },
        "{mode:?}: {result:?}"
    );
    if ingested {
        assert!(
            views
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|(_, sources)| sources == &[hex(&sha256(RESPONSE))])
        );
    }
    assert_no_spools(root.path());
    engine.finish_subagent_plan(&started).unwrap();
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
    if matches!(mode, Mode::Automatic)
        && let Some(path) = std::env::var_os("IRMIND_SYNTHETIC_SUBAGENT_SOURCE_EXPORT")
    {
        std::fs::copy(root.path().join("tool-child.irmind"), path).unwrap();
    }
}
fn assert_no_spools(path: &std::path::Path) {
    for item in std::fs::read_dir(path).unwrap() {
        let item = item.unwrap();
        if item.file_type().unwrap().is_dir() {
            if item.file_name() == "spool" {
                assert_eq!(std::fs::read_dir(item.path()).unwrap().count(), 0);
            } else {
                assert_no_spools(&item.path());
            }
        }
    }
}

fn control_task(
    analyst: &Engine<'_>,
    observed: &Objects,
    case: &CaseId,
    task: SubagentDigest,
    mode: Mode,
) {
    if !matches!(mode, Mode::Approve | Mode::Deny | Mode::Cancel) {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if matches!(mode, Mode::Cancel) && observed.reads.load(Ordering::SeqCst) != 0 {
            assert!(analyst.cancel_live_subagent_task(case, task).unwrap());
            return;
        }
        if let Some(request) = analyst.pending_approvals(case).unwrap().into_iter().next() {
            assert_eq!(observed.reads.load(Ordering::SeqCst), 0);
            if matches!(mode, Mode::Approve) {
                analyst.approve(case, &request.id).unwrap();
            } else {
                analyst
                    .deny(case, &request.id, "Synthetic transfer denied")
                    .unwrap();
            }
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("task control did not become available for {mode:?}");
}
fn parent_listing(engine: &Engine<'_>, case: &CaseId) {
    engine
        .request_tool_as_analyst(
            case,
            ProposedCall {
                tool: Tool::ObjectList,
                args: BTreeMap::from([
                    ("source".into(), "storage-test".into()),
                    ("scheme".into(), "s3".into()),
                    ("container".into(), "synthetic-bucket".into()),
                    ("prefix".into(), "logs/".into()),
                    ("from".into(), "2026-11-01T00:00:00Z".into()),
                    ("to".into(), "2026-11-01T23:59:59Z".into()),
                    ("limit".into(), "10".into()),
                ]),
            },
            &CancellationToken::new(),
        )
        .unwrap();
}

fn start_object_plan(
    engine: &Engine<'_>,
    case: &CaseId,
    scope: &str,
    mode: Mode,
    cancel: &CancellationToken,
) -> irmind_app::subagents::StartedSubagentPlan {
    let mut task = proposal(100_000);
    task.type_id = "cloud".into();
    task.budget.rounds = 4;
    task.budget.cloud_bytes = if matches!(mode, Mode::OverBudget) {
        1
    } else {
        10_000
    };
    task.remote_scope = Some(irmind_domain::CaseScope::parse(scope).unwrap());
    let prepared = engine
        .prepare_subagent_plan(
            case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![task],
            SubagentResources::default(),
            cancel,
        )
        .unwrap();
    engine
        .admit_subagent_plan(
            &prepared,
            &prepared.preview().automatic_start().unwrap(),
            cancel,
        )
        .unwrap()
        .unwrap()
}
