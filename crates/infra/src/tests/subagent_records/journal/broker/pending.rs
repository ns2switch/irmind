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
    let message = engine
        .deny(
            &history.case,
            &request,
            "Cancel the closed synthetic task request",
        )
        .unwrap();
    assert!(message.contains("Subagent request denied"));
    assert!(engine.pending_approvals(&history.case).unwrap().is_empty());
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}

fn publish_pending(
    store: &LocalStore,
    root: &std::path::Path,
    history: &mut History,
    started: &irmind_app::subagents::StartedSubagentPlan,
) -> String {
    publish_request(
        store,
        root,
        history,
        started,
        &Tool::ThreatIntelExternal,
        &BTreeMap::from([("ioc".into(), "203.0.113.77".into())]),
    )
}

fn publish_request(
    store: &LocalStore,
    root: &std::path::Path,
    history: &mut History,
    started: &irmind_app::subagents::StartedSubagentPlan,
    tool: &Tool,
    arguments: &BTreeMap<String, String>,
) -> String {
    history.entries = store.entries(&history.case).unwrap();
    let prefix_len = history.entries.len();
    let entry = branch_entry(
        history,
        started.plan(),
        1,
        SubagentBranchPayload::ToolProposal(BranchToolProposal {
            call_id: "pending_lookup".into(),
            tool: tool.as_str().into(),
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
            tool: tool.clone(),
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
    history.append(
        AuditEventKind::NeedsApproval,
        serde_json::to_string(&serde_json::json!({
            "version":1,"id":request,"mode":"attended","decision_seq":pending.decision_seq(),
            "tool":tool.as_str(),"args":arguments,"challenge":hex(&pending.challenge())
        }))
        .unwrap(),
        false,
    );
    store.append_batch(&history.entries[prefix_len..]).unwrap();
    request
}

#[test]
fn a_narrower_case_preserves_historical_task_requests_and_allows_denial_without_dispatch() {
    let mut history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let from = "2026-11-01T00:00:00Z";
    let to = "2026-11-01T23:59:59Z";
    let scope = format!(
        "v3;sources=storage;accounts=;projects=;hosts=;objects=s3://bucket/AWSLogs/123/;from={from};to={to}"
    );
    engine.change_scope(&history.case, &scope).unwrap();
    let mut task = proposal(100_000);
    task.type_id = "cloud".into();
    task.remote_scope = Some(irmind_domain::CaseScope::parse(&scope).unwrap());
    task.budget.cloud_bytes = 100_000_000;
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
    let request = publish_request(
        store.as_ref(),
        root.path(),
        &mut history,
        &started,
        &Tool::ObjectRead,
        &BTreeMap::from([
            ("source".into(), "storage".into()),
            ("scheme".into(), "s3".into()),
            ("container".into(), "bucket".into()),
            ("key".into(), "AWSLogs/123/events.json".into()),
            ("from".into(), from.into()),
            ("to".into(), to.into()),
            ("etag".into(), "synthetic-etag".into()),
            ("max_bytes".into(), "100000000".into()),
        ]),
    );
    engine.verify(&history.case).unwrap();
    engine.change_scope(&history.case, "local").unwrap();
    engine.verify(&history.case).unwrap();
    assert_eq!(engine.pending_approvals(&history.case).unwrap().len(), 1);
    assert!(engine.approve(&history.case, &request).is_err());
    engine
        .cancel_subagent_task(&started, started.plan().tasks[0].task_id)
        .unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    engine
        .deny(
            &history.case,
            &request,
            "Reject the obsolete synthetic transfer",
        )
        .unwrap();
    assert!(engine.pending_approvals(&history.case).unwrap().is_empty());
    assert!(
        !store
            .entries(&history.case)
            .unwrap()
            .iter()
            .any(|entry| matches!(
                entry.kind,
                AuditEventKind::ToolDispatch | AuditEventKind::ApprovalGranted
            ))
    );
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}
