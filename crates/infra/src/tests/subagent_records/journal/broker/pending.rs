use super::*;
use irmind_app::subagents::{
    BranchToolProposal, CheckedBranchChunk, SubagentBranchPayload, SubagentBranchStore,
};

#[test]
fn task_pending_requests_keep_their_owner_after_cancellation_and_cannot_use_parent_dispatch() {
    let mut history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let started = tools::start(&engine, &history);
    let request = publish_pending(store.as_ref(), root.path(), &mut history, &started);
    engine.verify(&history.case).unwrap();
    assert_eq!(engine.pending_approvals(&history.case).unwrap().len(), 1);
    let before = store.entries(&history.case).unwrap().len();
    for result in [
        engine.approve(&history.case, &request),
        engine.edit_approval(
            &history.case,
            &request,
            BTreeMap::from([("ioc".into(), "example.com".into())]),
        ),
    ] {
        assert!(result.unwrap_err().to_string().contains("subagent"));
    }
    assert_eq!(store.entries(&history.case).unwrap().len(), before);
    let result = engine
        .cancel_subagent_task(&started, started.plan().tasks[0].task_id)
        .unwrap();
    assert_eq!(
        result.pending_approvals,
        vec![SubagentDigest::parse(&request).unwrap()]
    );
    engine.finish_subagent_plan(&started).unwrap();
    assert!(
        engine
            .approve(&history.case, &request)
            .unwrap_err()
            .to_string()
            .contains("subagent")
    );
    assert!(
        !store
            .entries(&history.case)
            .unwrap()
            .iter()
            .any(|entry| entry.kind == AuditEventKind::ApprovalGranted)
    );
    engine.verify(&history.case).unwrap();
}

fn publish_pending(
    store: &LocalStore,
    root: &std::path::Path,
    history: &mut History,
    started: &irmind_app::subagents::StartedSubagentPlan,
) -> String {
    history.entries = store.entries(&history.case).unwrap();
    let prefix_len = history.entries.len();
    let arguments = BTreeMap::from([("ioc".into(), "203.0.113.77".into())]);
    let entry = branch_entry(
        history,
        started.plan(),
        1,
        SubagentBranchPayload::ToolProposal(BranchToolProposal {
            call_id: "pending_lookup".into(),
            tool: Tool::ThreatIntelExternal.as_str().into(),
            arguments: arguments.clone(),
            allocation_sha256: started.allocation().identity().unwrap(),
            tainted: true,
            source: None,
            guarded_excerpt: "Synthetic indicator".into(),
        }),
        SubagentDigest::from_bytes([0; 32]),
    );
    let chunk =
        CheckedBranchChunk::from_entries(&[entry], &history.agent.public_key(), &history.verifier)
            .unwrap();
    let branches = ParquetStore::open(root).unwrap();
    branches
        .publish(
            branches
                .stage(&history.case, &chunk, &CancellationToken::new())
                .unwrap(),
        )
        .unwrap();
    history.record(&chunk.checkpoint(None, vec![]).unwrap(), false);
    let case = store.get_case(&history.case).unwrap();
    let Decision::NeedsApproval(pending) = irmind_domain::evaluate_with_rules(
        &case,
        ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: arguments.clone(),
        },
        history.entries.len() as u64 + 1,
        ExecutionMode::Attended,
        10,
        &PolicyRules::default(),
    ) else {
        panic!("expected a synthetic approval")
    };
    let request = hex(&sha256(&pending.challenge()));
    history.append(AuditEventKind::NeedsApproval, serde_json::to_string(&serde_json::json!({
        "version":1,"id":request,"mode":"attended","decision_seq":pending.decision_seq(),
        "tool":Tool::ThreatIntelExternal.as_str(),"args":arguments,"challenge":hex(&pending.challenge())
    })).unwrap(), false);
    store.append_batch(&history.entries[prefix_len..]).unwrap();
    request
}
