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
    fn output_profile(&self) -> irmind_app::ModelOutputProfile {
        irmind_app::ModelOutputProfile::known(2048, false).unwrap()
    }
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
                cache: None,
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

#[test]
fn report_coverage_resolves_the_same_skill_load_position_in_two_signed_branches() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let engine = engine.with_large_case_pipeline(store.clone(), Arc::new(json_source_parser()));
    let cancel = CancellationToken::new();
    let make_task = || {
        let mut task = proposal(100_000);
        task.skill = Some(irmind_domain::SkillName::parse("windows-triage").unwrap());
        task
    };
    let prepared = engine
        .prepare_subagent_plan(
            &history.case,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![make_task(), make_task()],
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
    for task in &started.plan().tasks {
        let result = engine
            .run_subagent_task(&started, task.task_id, &child_model(true), &cancel)
            .unwrap();
        assert_eq!(result.status, SubagentStatus::Completed);
    }
    engine.finish_subagent_plan(&started).unwrap();

    let coverage = engine.report_coverage(&history.case, &cancel).unwrap();
    let hits = coverage
        .delegated_skill_gaps
        .iter()
        .filter(|gap| gap.gap_index == 0)
        .collect::<Vec<_>>();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].load_sequence, hits[1].load_sequence);
    assert_ne!(hits[0].task_id, hits[1].task_id);
    assert_ne!(hits[0].load_sha256, hits[1].load_sha256);
    assert_ne!(hits[0].checkpoint, hits[1].checkpoint);
    let entries = store.entries(&history.case).unwrap();
    for gap in &hits {
        assert_report_gap_load(&store, &history, &entries, gap, &cancel);
    }
    assert_eq!(
        irmind_app::v10_proofs::ReportCoverageV2::decode(&coverage.encode().unwrap()).unwrap(),
        coverage
    );
    let plan = store
        .plan_cited_report(
            &engine,
            &history.case,
            irmind_app::ReportDocumentLanguage::English,
            irmind_app::ReportDocumentFormat::Markdown,
            &cancel,
        )
        .unwrap();
    let receipt = engine
        .publish_cited_report(&history.case, plan, &cancel)
        .unwrap();
    let stored = store
        .read_addressed_report_proof(&history.case, 2, receipt.coverage, &cancel)
        .unwrap();
    assert_eq!(
        irmind_app::v10_proofs::ReportCoverageV2::decode(&stored).unwrap(),
        coverage
    );
    let rendered = store
        .read_addressed_report_proof(&history.case, 3, receipt.rendered_sha256, &cancel)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    for gap in hits {
        assert!(rendered.contains(&hex(&gap.task_id)));
    }
    engine.verify(&history.case).unwrap();
    engine.seal(&history.case).unwrap();
    let path = root.path().join("delegated-report.irmind");
    CaseExporter::export_case(store.as_ref(), &history.case, &path, &cancel).unwrap();
    verify_export_expected(&path, Some(&hex(&sha256(&history.analyst.public_key())))).unwrap();
}

fn assert_report_gap_load(
    store: &LocalStore,
    history: &History,
    entries: &[SignedEntry],
    gap: &irmind_app::v10_proofs::V10DelegatedSkillGap,
    cancel: &CancellationToken,
) {
    use irmind_app::subagents::{
        BranchChunkRef, CheckedBranchChunk, SubagentBranchPayload, SubagentBranchStore,
        SubagentCheckpointV1,
    };
    let checkpoint = &entries[usize::try_from(gap.checkpoint.sequence - 1).unwrap()];
    assert_eq!(checkpoint.hash, gap.checkpoint.entry_sha256);
    assert_eq!(checkpoint.kind, AuditEventKind::SubagentCheckpointV1);
    let (_, payload) = checkpoint.payload.split_once(':').unwrap();
    let parsed = SubagentCheckpointV1::decode(&::hex::decode(payload).unwrap()).unwrap();
    assert_eq!(parsed.task_id.as_bytes(), &gap.task_id);
    let reference = BranchChunkRef::new(parsed.chunk_sha256, parsed.chunk_bytes).unwrap();
    let material = store
        .parquet
        .read(&history.case, &reference, cancel)
        .unwrap();
    let decoded = CheckedBranchChunk::decode(
        material.as_bytes(),
        &history.agent.public_key(),
        &history.verifier,
    )
    .unwrap();
    let load = &decoded.entries()[usize::try_from(gap.load_sequence - parsed.first).unwrap()];
    assert_eq!(load.hash.as_bytes(), &gap.load_sha256);
    assert!(matches!(
        load.body.payload,
        SubagentBranchPayload::SkillLoad(_)
    ));
}
