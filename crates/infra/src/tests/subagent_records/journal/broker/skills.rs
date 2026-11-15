use super::*;
use irmind_app::subagents::SubagentStatus;

#[test]
fn child_pinned_method_is_guarded_committed_before_model_context_and_verifiable_offline() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let mut task = proposal(100_000);
    task.skill = Some(irmind_domain::SkillName::parse("windows-triage").unwrap());
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![task],
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
    let model = child_model(true);
    let result = engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    assert_eq!(result.status, SubagentStatus::Completed);
    assert_eq!(result.usage.calls, 1);
    let requests = model.requests.lock().unwrap();
    let messages = &requests[0].messages;
    let method = messages
        .iter()
        .find(|message| message.tool_call_id.as_deref() == Some("initial_skill"))
        .unwrap();
    assert!(method.content.starts_with("<UNTRUSTED_"));
    assert!(method.content.contains("Establish coverage"));
    assert!(!messages[0].content.contains("Establish coverage"));
    assert!(
        requests[0]
            .tools
            .iter()
            .any(|tool| tool.name == "skill_read")
    );
    assert!(
        !requests[0]
            .tools
            .iter()
            .any(|tool| tool.name == "evidence_search")
    );
    drop(requests);
    assert!(
        !store
            .entries(&history.case)
            .unwrap()
            .iter()
            .any(|entry| entry.kind == AuditEventKind::SkillLoadV1)
    );
    engine.verify(&history.case).unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    engine.seal(&history.case).unwrap();
    let path = root.path().join("child-skill.irmind");
    CaseExporter::export_case(store.as_ref(), &history.case, &path, &cancel).unwrap();
    verify_export_expected(&path, Some(&hex(&sha256(&history.analyst.public_key())))).unwrap();
}

struct RepeatMethod(std::sync::atomic::AtomicUsize);
#[async_trait]
impl LlmPort for RepeatMethod {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let first = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
        let calls = if first {
            (1..=5)
                .map(|n| {
                    ModelToolCall::from_proposal(
                        &format!("load_{n}"),
                        ProposedCall {
                            tool: Tool::SkillRead,
                            args: BTreeMap::from([("name".into(), "windows-triage".into())]),
                        },
                    )
                    .unwrap()
                })
                .collect()
        } else {
            vec![]
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic methodology review.".into(),
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
fn sibling_method_loads_share_one_eight_read_budget_without_resetting_it() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let mut task = proposal(100_000);
    task.skill = Some(irmind_domain::SkillName::parse("windows-triage").unwrap());
    let mut other = proposal(100_000);
    other.skill = task.skill.clone();
    let cancel = CancellationToken::new();
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![task, other],
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
    for (index, task) in started.plan().tasks.iter().enumerate() {
        let model = RepeatMethod(std::sync::atomic::AtomicUsize::new(0));
        let result = engine
            .run_subagent_task(&started, task.task_id, &model, &cancel)
            .unwrap();
        assert_eq!(
            result.status,
            if index == 0 {
                SubagentStatus::Completed
            } else {
                SubagentStatus::Partial
            }
        );
    }
    engine.verify(&history.case).unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    let mut journal = SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
    for entry in store.entries(&history.case).unwrap() {
        journal.accept(&entry, &history.verifier).unwrap();
    }
    let (loaded, limited) = count_method_receipts(store.as_ref(), &history, &journal);
    assert_eq!(loaded, 8);
    assert_eq!(limited, 4);
    engine.seal(&history.case).unwrap();
}

fn count_method_receipts(
    store: &LocalStore,
    history: &History,
    journal: &SubagentJournal,
) -> (usize, usize) {
    use irmind_app::subagents::{
        BranchMaterialVerifier, CheckedBranchChunk, SubagentBranchPayload,
    };
    let cancel = CancellationToken::new();
    let mut material = BranchMaterialVerifier::new(journal).unwrap();
    let mut receipts = irmind_app::SkillReceiptVerifier::default();
    for entry in store.entries(&history.case).unwrap() {
        receipts.accept(&entry, &TomlSkillCompiler).unwrap();
    }
    let mut loaded = 0;
    let mut limited = 0;
    while let Some(reference) = material.next_reference().unwrap() {
        use irmind_app::subagents::SubagentBranchStore;
        let bytes = store
            .parquet
            .read(&history.case, &reference, &cancel)
            .unwrap();
        let chunk = CheckedBranchChunk::decode(
            bytes.as_bytes(),
            &history.agent.public_key(),
            &history.verifier,
        )
        .unwrap();
        for entry in chunk.entries() {
            if let SubagentBranchPayload::SkillLoad(value) = &entry.body.payload {
                let load = irmind_app::SkillLoadV1::decode(value).unwrap();
                match load.result() {
                    irmind_app::SkillLoadResult::Loaded => loaded += 1,
                    irmind_app::SkillLoadResult::Limit => {
                        limited += 1;
                        assert!(load.text().is_empty());
                    }
                    _ => panic!("unexpected methodology result"),
                }
            }
        }
        let descriptor = material.next_descriptor().unwrap().unwrap();
        material
            .accept(
                &descriptor,
                bytes.as_bytes(),
                &history.verifier,
                &mut receipts,
                &TomlSkillCompiler,
            )
            .unwrap();
    }
    material.finish().unwrap();
    (loaded, limited)
}
