use super::*;
use irmind_app::subagents::TaskQueryPartialReason;

struct PartialQuery(bool);
impl TaskEvidenceQueries for PartialQuery {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        let text = r#"Synthetic data: {"partial":true,"truncated":true}."#.into();
        Ok(if self.0 {
            TaskEvidenceResult::PartialText {
                text,
                reason: TaskQueryPartialReason::Sampling,
            }
        } else {
            TaskEvidenceResult::Text(text)
        })
    }
}

#[test]
fn a_completed_model_reply_cannot_clear_typed_query_partial_state_in_signed_results_or_exports() {
    for partial in [false, true] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let (store, engine) = stored_history_engine_with_queries(
            root.path(),
            &history,
            &[],
            Arc::new(PartialQuery(partial)),
        );
        let started = start(&engine, &history);
        let model = ToolModel {
            requests: std::sync::Mutex::new(vec![]),
            repeat: false,
            tool: Tool::GraphSummary,
        };
        let result = engine
            .run_subagent_task(
                &started,
                started.plan().tasks[0].task_id,
                &model,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            result.status,
            if partial {
                SubagentStatus::Partial
            } else {
                SubagentStatus::Completed
            }
        );
        assert_eq!(result.usage.calls, 1);
        let requests = model.requests.lock().unwrap();
        assert!(
            requests[1]
                .messages
                .iter()
                .any(|message| message.role == irmind_app::MessageRole::Tool
                    && message.content.contains("UNTRUSTED_")
                    && message.content.contains("Synthetic data:"))
        );
        drop(requests);
        engine.finish_subagent_plan(&started).unwrap();
        verify_and_export(store.as_ref(), &engine, &history, root.path());
        let bytes = std::fs::read(root.path().join("tool-child.irmind")).unwrap();
        let marker = if partial {
            b"\"partial\":true".as_slice()
        } else {
            b"\"partial\":false".as_slice()
        };
        assert!(bytes.windows(marker.len()).any(|window| window == marker));
    }
}

#[test]
fn a_genuine_agent_signature_cannot_relabel_a_partial_branch_as_completed() {
    let history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine_with_queries(
        root.path(),
        &history,
        &[],
        Arc::new(PartialQuery(true)),
    );
    let started = start(&engine, &history);
    let model = ToolModel {
        requests: std::sync::Mutex::new(vec![]),
        repeat: false,
        tool: Tool::GraphSummary,
    };
    engine
        .run_subagent_task(
            &started,
            started.plan().tasks[0].task_id,
            &model,
            &CancellationToken::new(),
        )
        .unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    engine.verify(&history.case).unwrap();
    let (forged, chunks) = falsely_completed_history(store.as_ref(), &history);
    let copy = tempfile::tempdir().unwrap();
    let (_, engine) = stored_history_engine(copy.path(), &forged, &chunks);
    assert!(engine.verify(&history.case).is_err());
}

fn decode<T: SubagentRecord>(entry: &SignedEntry) -> T {
    T::decode(&hex::decode(entry.payload.split_once(':').unwrap().1).unwrap()).unwrap()
}

fn falsely_completed_history(
    store: &LocalStore,
    original: &History,
) -> (History, Vec<irmind_app::subagents::CheckedBranchChunk>) {
    use irmind_app::subagents::{
        BranchChunkRef, CheckedBranchChunk, SubagentBranchEntry, SubagentBranchPayload,
        SubagentBranchStore, SubagentCheckpointV1, SubagentResultV1,
    };
    let entries = store.entries(&original.case).unwrap();
    let mut chunks = Vec::new();
    let mut replacement = None;
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SubagentCheckpointV1)
    {
        let checkpoint: SubagentCheckpointV1 = decode(entry);
        let reference =
            BranchChunkRef::new(checkpoint.chunk_sha256, checkpoint.chunk_bytes).unwrap();
        let bytes = store
            .parquet
            .read(&original.case, &reference, &CancellationToken::new())
            .unwrap();
        let chunk = CheckedBranchChunk::decode(
            bytes.as_bytes(),
            &original.agent.public_key(),
            &original.verifier,
        )
        .unwrap();
        if !checkpoint.terminal {
            chunks.push(chunk);
            continue;
        }
        let mut signed: Vec<SubagentBranchEntry> = Vec::new();
        let mut terminal = None;
        for item in chunk.entries() {
            let mut body = item.body.clone();
            if let SubagentBranchPayload::Terminal(value) = &mut body.payload {
                assert_eq!(value.status, SubagentStatus::Partial);
                value.status = SubagentStatus::Completed;
                terminal = Some(value.clone());
            }
            if let Some(previous) = signed.last() {
                body.prev = previous.hash;
            }
            signed.push(SubagentBranchEntry::sign(body, &original.agent).unwrap());
        }
        let changed = CheckedBranchChunk::from_entries(
            &signed,
            &original.agent.public_key(),
            &original.verifier,
        )
        .unwrap();
        let updated = changed
            .checkpoint(
                checkpoint.previous_checkpoint,
                checkpoint.admitted_sources.clone(),
            )
            .unwrap();
        let result = SubagentResultV1::from_terminal(&updated, &terminal.unwrap()).unwrap();
        replacement = Some((checkpoint.identity().unwrap(), updated, result));
        chunks.push(changed);
    }
    let (old, updated, result) = replacement.unwrap();
    (
        resign_main(entries, old, &updated, &result, original),
        chunks,
    )
}

fn resign_main(
    entries: Vec<SignedEntry>,
    old: irmind_app::subagents::SubagentDigest,
    updated: &irmind_app::subagents::SubagentCheckpointV1,
    result: &irmind_app::subagents::SubagentResultV1,
    original: &History,
) -> History {
    use irmind_app::subagents::SubagentCheckpointV1;
    let mut history = History::new();
    history.entries.clear();
    for mut entry in entries {
        if entry.kind == AuditEventKind::SubagentCheckpointV1
            && decode::<SubagentCheckpointV1>(&entry).identity().unwrap() == old
        {
            entry.payload = updated.audit_payload().unwrap();
        } else if entry.kind == AuditEventKind::SubagentResultV1 {
            entry.payload = result.audit_payload().unwrap();
        } else if entry.kind == AuditEventKind::SubagentReservationV1 {
            let mut value: SubagentReservationV1 = decode(&entry);
            if value.cause_sha256 == old {
                value.cause_sha256 = updated.identity().unwrap();
                entry.payload = value.audit_payload().unwrap();
            }
        }
        entry.prev = history.entries.last().map_or([0; 32], |entry| entry.hash);
        entry.hash = sha256(&entry.canonical());
        entry.sig = if entry.actor == Actor::Analyst {
            history.analyst.sign(&entry.hash)
        } else {
            history.agent.sign(&entry.hash)
        }
        .unwrap();
        original
            .verifier
            .verify(&entry.public_key, &entry.hash, &entry.sig)
            .unwrap();
        history.entries.push(entry);
    }
    history
}
