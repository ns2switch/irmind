use super::*;
use irmind_app::subagents::SubagentStatus;
use irmind_domain::EvidenceHash;

fn source(
    root: &std::path::Path,
    store: &LocalStore,
    engine: &Engine<'_>,
    case: &CaseId,
    name: &str,
    bytes: &[u8],
) -> EvidenceHash {
    std::fs::write(root.join(name), bytes).unwrap();
    irmind_app::LargeCaseUseCases {
        engine,
        store,
        parser: &json_source_parser(),
    }
    .ingest_local(case, root, name, false, &CancellationToken::new())
    .unwrap();
    let hash = EvidenceHash::from_bytes(sha256(bytes));
    store.put_evidence(case, hash.as_str(), bytes).unwrap();
    hash
}
struct FindingModel {
    hash: String,
    sent: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl LlmPort for FindingModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let calls = if self.sent.swap(true, std::sync::atomic::Ordering::SeqCst) {
            vec![]
        } else {
            vec![
                ModelToolCall::from_proposal(
                    "finding_1",
                    ProposedCall {
                        tool: Tool::CaseAddFinding,
                        args: BTreeMap::from([
                            ("kind".into(), "hypothesis".into()),
                            ("value".into(), "Synthetic bounded hypothesis".into()),
                            ("evidence_hash".into(), self.hash.clone()),
                            ("supporting_evidence".into(), self.hash.clone()),
                        ]),
                    },
                )
                .unwrap(),
            ]
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic finding review.".into(),
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
fn child_findings_are_source_bounded_agent_signed_and_only_the_analyst_confirms_them() {
    for outside in [false, true] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let (store, engine) = stored_history_engine(root.path(), &history, &[]);
        let first = source(
            root.path(),
            store.as_ref(),
            &engine,
            &history.case,
            "first.json",
            br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"Login","user":"first"}"#,
        );
        let second = source(
            root.path(),
            store.as_ref(),
            &engine,
            &history.case,
            "second.json",
            br#"{"eventTime":"2026-11-01T00:00:01Z","eventName":"Login","user":"second"}"#,
        );
        let mut task = proposal(100_000);
        task.sources = vec![first.clone()];
        let cancel = CancellationToken::new();
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
        let model = FindingModel {
            hash: if outside { second } else { first }.as_str().into(),
            sent: std::sync::atomic::AtomicBool::new(false),
        };
        let result = engine
            .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
            .unwrap();
        assert_eq!(
            result.status,
            if outside {
                SubagentStatus::Partial
            } else {
                SubagentStatus::Completed
            }
        );
        engine.finish_subagent_plan(&started).unwrap();
        let findings = engine.findings(&history.case).unwrap();
        assert_eq!(findings.len(), usize::from(!outside));
        if let Some(finding) = findings.first() {
            assert!(!finding.confirmed);
            let entry = store
                .entries(&history.case)
                .unwrap()
                .into_iter()
                .find(|entry| entry.kind == AuditEventKind::FindingProposed)
                .unwrap();
            assert_eq!(entry.actor, history.agent.actor());
            engine.confirm_finding(&history.case, &finding.id).unwrap();
            assert!(engine.findings(&history.case).unwrap()[0].confirmed);
        }
        engine.verify(&history.case).unwrap();
        engine.seal(&history.case).unwrap();
        let path = root.path().join("finding.irmind");
        CaseExporter::export_case(store.as_ref(), &history.case, &path, &cancel).unwrap();
        verify_export_expected(&path, Some(&hex(&sha256(&history.analyst.public_key())))).unwrap();
    }
}

fn verify_prefix(
    history: &History,
    entries: &[SignedEntry],
    store: &LocalStore,
) -> Result<(), AppError> {
    let mut journal = SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
    let mut receipts = irmind_app::SkillReceiptVerifier::default();
    for entry in entries {
        journal.accept(entry, &history.verifier)?;
        receipts.accept(entry, &TomlSkillCompiler)?;
    }
    journal.verify_stored_branches(
        &store.parquet,
        &history.verifier,
        &mut receipts,
        &TomlSkillCompiler,
        &CancellationToken::new(),
    )
}
#[test]
fn a_genuine_agent_signature_cannot_substitute_the_committed_finding_or_its_sources() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let first = source(
        root.path(),
        store.as_ref(),
        &engine,
        &history.case,
        "first.json",
        br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"Login","user":"first"}"#,
    );
    let second = source(
        root.path(),
        store.as_ref(),
        &engine,
        &history.case,
        "second.json",
        br#"{"eventTime":"2026-11-01T00:00:01Z","eventName":"Login","user":"second"}"#,
    );
    let mut task = proposal(100_000);
    task.sources = vec![first.clone()];
    let cancel = CancellationToken::new();
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
    let model = FindingModel {
        hash: first.as_str().into(),
        sent: std::sync::atomic::AtomicBool::new(false),
    };
    engine
        .run_subagent_task(&started, started.plan().tasks[0].task_id, &model, &cancel)
        .unwrap();
    let mut prefix: Vec<_> = store
        .entries(&history.case)
        .unwrap()
        .into_iter()
        .take_while(|entry| entry.kind != AuditEventKind::FindingProposed)
        .collect();
    let effect = store
        .entries(&history.case)
        .unwrap()
        .into_iter()
        .find(|entry| entry.kind == AuditEventKind::FindingProposed)
        .unwrap();
    prefix.push(effect);
    verify_prefix(&history, &prefix, store.as_ref()).unwrap();
    for replace_source in [false, true] {
        let mut changed = prefix.clone();
        let last = changed.last_mut().unwrap();
        let mut finding: irmind_app::Finding = serde_json::from_str(&last.payload).unwrap();
        if replace_source {
            finding.evidence_hash = second.as_str().into();
            last.evidence = Some(second.as_str().into());
        } else {
            finding.value = "A different unapproved conclusion".into();
        }
        last.payload = serde_json::to_string(&finding).unwrap();
        last.hash = sha256(&last.canonical());
        last.sig = history.agent.sign(&last.hash).unwrap();
        history
            .verifier
            .verify(&last.public_key, &last.hash, &last.sig)
            .unwrap();
        assert!(verify_prefix(&history, &changed, store.as_ref()).is_err());
    }
}
