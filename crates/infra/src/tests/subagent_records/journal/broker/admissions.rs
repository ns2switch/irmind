use super::*;
use irmind_app::subagents::{
    BranchToolProposal, BranchToolResult, CheckedBranchChunk, SubagentBranchPayload,
    SubagentBranchStore, TaskDispatchAttribution,
};

#[test]
fn a_task_source_admission_requires_its_own_prior_attributed_receipt_and_matching_branch_result() {
    let mut history = History::new();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &[]);
    let cancel = CancellationToken::new();
    let started = start_remote(&engine, &history);
    let EffectFixture {
        chunk,
        reservation,
        decision,
        payload,
        proposal_hash,
    } = dispatched_remote(store.as_ref(), &mut history, &started);
    // Genuine mapped acquisition receipts, not a model-supplied source hash.
    let bytes =
        br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"GetRole","user":"synthetic-role"}"#;
    std::fs::write(root.path().join("cloud-result.json"), bytes).unwrap();
    irmind_app::LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &json_source_parser(),
    }
    .ingest_local(
        &history.case,
        root.path(),
        "cloud-result.json",
        true,
        &cancel,
    )
    .unwrap();
    history.entries = store.entries(&history.case).unwrap();
    let prefix = history.entries.len();
    let source = SubagentDigest::from_bytes(sha256(bytes));
    let before_receipt = history.entries.clone();
    history.append(AuditEventKind::ToolResult, payload, false);
    let receipt = history.entries.last_mut().unwrap();
    receipt.evidence = Some(hex(source.as_bytes()));
    receipt.hash = sha256(&receipt.canonical());
    receipt.sig = history.agent.sign(&receipt.hash).unwrap();
    let result = branch_entry(
        &history,
        started.plan(),
        2,
        SubagentBranchPayload::ToolResult(BranchToolResult {
            call_id: "cloud_read".into(),
            proposal_sha256: proposal_hash,
            decision_audit_sha256: decision,
            reservation_sha256: reservation.identity().unwrap(),
            guarded_text: "Synthetic source acquired".into(),
            sources: vec![],
            partial: false,
        }),
        chunk.entries()[0].hash,
    );
    assert_wrong_branch_rejected(store.as_ref(), &history, &chunk, &result, source);
    let result_chunk = publish(&store, &history, &[result]);
    let result_checkpoint = result_chunk
        .checkpoint(
            Some(chunk.checkpoint(None, vec![]).unwrap().identity().unwrap()),
            vec![source],
        )
        .unwrap();
    assert_without_receipt_rejected(&before_receipt, &history, &result_checkpoint);
    history.record(&result_checkpoint, false);
    store.append_batch(&history.entries[prefix..]).unwrap();
    engine.verify(&history.case).unwrap();
    engine
        .cancel_subagent_task(&started, started.plan().tasks[0].task_id)
        .unwrap();
    engine.finish_subagent_plan(&started).unwrap();
    tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
}

fn start_remote(
    engine: &Engine<'_>,
    history: &History,
) -> irmind_app::subagents::StartedSubagentPlan {
    let scope = "v1;sources=aws-test;accounts=123456789012;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-01T23:59:59Z";
    engine.change_scope(&history.case, scope).unwrap();
    let mut task = proposal(100_000);
    task.type_id = "cloud".into();
    task.remote_scope = Some(irmind_domain::CaseScope::parse(scope).unwrap());
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
    engine
        .admit_subagent_plan(
            &prepared,
            &prepared.preview().automatic_start().unwrap(),
            &cancel,
        )
        .unwrap()
        .unwrap()
}
struct EffectFixture {
    chunk: CheckedBranchChunk,
    reservation: SubagentReservationV1,
    decision: SubagentDigest,
    payload: String,
    proposal_hash: SubagentDigest,
}
fn dispatched_remote(
    store: &LocalStore,
    history: &mut History,
    started: &irmind_app::subagents::StartedSubagentPlan,
) -> EffectFixture {
    history.entries = store.entries(&history.case).unwrap();
    let prefix = history.entries.len();
    let args = BTreeMap::from([
        ("source".into(), "aws-test".into()),
        ("account".into(), "123456789012".into()),
        ("kind".into(), "role".into()),
        ("name".into(), "SyntheticRole".into()),
    ]);
    let entry = branch_entry(
        history,
        started.plan(),
        1,
        SubagentBranchPayload::ToolProposal(BranchToolProposal {
            call_id: "cloud_read".into(),
            tool: Tool::CloudIdentity.as_str().into(),
            arguments: args.clone(),
            allocation_sha256: started.allocation().identity().unwrap(),
            tainted: true,
            source: None,
            guarded_excerpt: String::new(),
        }),
        SubagentDigest::from_bytes([0; 32]),
    );
    let proposal_hash = entry.hash;
    let chunk = publish(store, history, &[entry]);
    let checkpoint = chunk.checkpoint(None, vec![]).unwrap();
    history.record(&checkpoint, false);
    let reservation = SubagentReservationV1::prepare(
        started.plan(),
        Some(started.plan().tasks[0].task_id),
        1,
        ReservationAction::ReserveRequest,
        ReservationPurpose::Tool,
        ReservationTransition {
            amount: SubagentResources {
                calls: 1,
                ..SubagentResources::default()
            },
            parent_operation: Some(started.allocation().operation_id),
            cause_sha256: checkpoint.identity().unwrap(),
            accounting_audit_sha256: None,
        },
    )
    .unwrap();
    history.record(&reservation, false);
    let attribution = TaskDispatchAttribution {
        version: 1,
        tool: Tool::CloudIdentity.as_str().into(),
        reserved_bytes: 0,
        task_id: started.plan().tasks[0].task_id,
        call_id: "cloud_read".into(),
        proposal_sha256: proposal_hash,
        reservation_sha256: reservation.identity().unwrap(),
        arguments_sha256: SubagentDigest::from_bytes(sha256(&serde_json::to_vec(&args).unwrap())),
        source_set_sha256: started.plan().tasks[0].source_set_sha256,
    };
    let payload = String::from_utf8(attribution.canonical().unwrap()).unwrap();
    let decision = history.append(AuditEventKind::Allowed, payload.clone(), false);
    store.append_batch(&history.entries[prefix..]).unwrap();
    EffectFixture {
        chunk,
        reservation,
        decision,
        payload,
        proposal_hash,
    }
}
fn publish(
    store: &LocalStore,
    history: &History,
    entries: &[irmind_app::subagents::SubagentBranchEntry],
) -> CheckedBranchChunk {
    let chunk =
        CheckedBranchChunk::from_entries(entries, &history.agent.public_key(), &history.verifier)
            .unwrap();
    store
        .parquet
        .publish(
            store
                .parquet
                .stage(&history.case, &chunk, &CancellationToken::new())
                .unwrap(),
        )
        .unwrap();
    chunk
}
fn assert_without_receipt_rejected(
    before: &[SignedEntry],
    history: &History,
    checkpoint: &irmind_app::subagents::SubagentCheckpointV1,
) {
    let mut missing = History::new();
    missing.entries = before.to_vec();
    missing.record(checkpoint, false);
    assert!(missing.replay().is_err());
    // A different task cannot borrow the receipt even with the genuine Agent key.
    let mut foreign = History::new();
    foreign.entries.clone_from(&history.entries);
    let mut changed = checkpoint.clone();
    changed.task_id = SubagentDigest::from_bytes([99; 32]);
    foreign.record(&changed, false);
    assert!(foreign.replay().is_err());
}

fn assert_wrong_branch_rejected(
    store: &LocalStore,
    history: &History,
    prior: &CheckedBranchChunk,
    result: &irmind_app::subagents::SubagentBranchEntry,
    source: SubagentDigest,
) {
    let mut body = result.body.clone();
    let SubagentBranchPayload::ToolResult(value) = &mut body.payload else {
        panic!("tool result expected");
    };
    value.decision_audit_sha256 = SubagentDigest::from_bytes([88; 32]);
    let changed = irmind_app::subagents::SubagentBranchEntry::sign(body, &history.agent).unwrap();
    let changed = publish(store, history, &[changed]);
    let checkpoint = changed
        .checkpoint(
            Some(prior.checkpoint(None, vec![]).unwrap().identity().unwrap()),
            vec![source],
        )
        .unwrap();
    let mut fork = History::new();
    fork.entries.clone_from(&history.entries);
    fork.record(&checkpoint, false);
    assert!(
        fork.replay().is_ok(),
        "the main receipt alone does not validate the branch effect"
    );
    assert!(super::findings::verify_prefix(&fork, &fork.entries, store).is_err());
}
