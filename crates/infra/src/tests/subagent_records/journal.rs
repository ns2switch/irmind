use super::*;
use irmind_app::subagents::{
    ReservationAction, ReservationPurpose, ReservationTransition, SubagentDigest, SubagentJournal,
    SubagentPlanApprovalV1, SubagentPlanContext, SubagentPlanDecision, SubagentPolicySnapshot,
    SubagentReservationV1, SubagentResources, SubagentSourceSetV1, SubagentTypeSnapshotV1,
};
use irmind_domain::AuditEventKind;

struct History {
    case: CaseId,
    analyst: LocalSigner,
    agent: LocalSigner,
    verifier: LocalVerifier,
    entries: Vec<SignedEntry>,
}
impl History {
    fn new() -> Self {
        let analyst = LocalSigner {
            key: SigningKey::from_bytes(&[42; 32]),
            actor: Actor::Analyst,
        };
        let agent = LocalSigner {
            key: SigningKey::from_bytes(&[43; 32]),
            actor: Actor::Agent(irmind_domain::AgentId::parse("skills-agent").unwrap()),
        };
        let verifier = LocalVerifier::from_signer(&analyst)
            .with_trusted_key(&agent.actor(), &agent.public_key())
            .unwrap();
        let mut value = Self {
            case: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            analyst,
            agent,
            verifier,
            entries: vec![],
        };
        value.append(
            AuditEventKind::CaseCreated,
            include_str!(
                "../../../../../docs/development/subagent-format-vectors/case-created-v4.json"
            )
            .into(),
            true,
        );
        value
    }
    fn append(&mut self, kind: AuditEventKind, payload: String, analyst: bool) -> SubagentDigest {
        let signer = if analyst { &self.analyst } else { &self.agent };
        let mut entry = SignedEntry {
            seq: self.entries.len() as u64 + 1,
            case_id: self.case.as_str().into(),
            at: 10,
            actor: signer.actor(),
            origin: if analyst { "Analyst" } else { "Agent" }.into(),
            kind,
            payload,
            evidence: None,
            prev: self.entries.last().map_or([0; 32], |e| e.hash),
            hash: [0; 32],
            sig: vec![],
            public_key: signer.public_key(),
        };
        entry.hash = sha256(&entry.canonical());
        entry.sig = signer.sign(&entry.hash).unwrap();
        let hash = SubagentDigest::from_bytes(entry.hash);
        self.entries.push(entry);
        hash
    }
    fn record<T: SubagentRecord>(&mut self, value: &T, analyst: bool) -> SubagentDigest {
        self.append(T::KIND, value.audit_payload().unwrap(), analyst)
    }
    fn plan(&mut self, tokens: u64) -> SubagentPlanV1 {
        let set = SubagentSourceSetV1::new(&self.case, 0, vec![]).unwrap();
        let kind = SubagentTypeSnapshotV1::new(&self.case, "triage").unwrap();
        self.record(&set, false);
        self.record(&kind, false);
        let prototype = SubagentPlanV1::decode(include_bytes!(
            "../../../../../docs/development/subagent-format-vectors/plan.json"
        ))
        .unwrap();
        let mut task = prototype.tasks[0].clone();
        task.type_snapshot_sha256 = kind.identity().unwrap();
        task.source_set_sha256 = set.identity().unwrap();
        task.budget.tokens = tokens;
        task.budget.calls = 10;
        let context = SubagentPlanContext {
            parent_checkpoint_sha256: SubagentDigest::from_bytes(self.entries.last().unwrap().hash),
            budget_checkpoint_sha256: SubagentDigest::from_bytes(self.entries[0].hash),
            policy: SubagentPolicySnapshot::new(&PolicyRules::default()).unwrap(),
            case_limits: SubagentResources {
                tokens: 2_000_000,
                calls: 1000,
                rounds: 25,
                cloud_bytes: 536_870_912_000,
            },
            usage: SubagentResources::default(),
            prior_reserved: SubagentResources::default(),
        };
        SubagentPlanV1::prepare(
            &self.case,
            &prototype.turn_id,
            1,
            context,
            vec![task],
            SubagentResources::default(),
            prototype.deadline_at,
        )
        .unwrap()
    }
    fn replay(&self) -> Result<SubagentResources, AppError> {
        let mut journal = SubagentJournal::new(self.case.clone(), self.agent.actor()).unwrap();
        for entry in &self.entries {
            journal.accept(entry, &self.verifier)?;
        }
        journal.outstanding().map_err(|_| AppError::InvalidChain(0))
    }
}

fn transition(
    plan: &SubagentPlanV1,
    action: ReservationAction,
    parent: Option<SubagentDigest>,
    cause: SubagentDigest,
) -> SubagentReservationV1 {
    SubagentReservationV1::prepare(
        plan,
        None,
        0,
        action,
        ReservationPurpose::Plan,
        ReservationTransition {
            amount: plan.reservation,
            parent_operation: parent,
            cause_sha256: cause,
            accounting_audit_sha256: None,
        },
    )
    .unwrap()
}

#[test]
fn authenticated_plan_requires_whole_plan_analyst_consent_and_cannot_start_twice() {
    let mut history = History::new();
    let plan = history.plan(500_001);
    let plan_hash = history.record(&plan, false);
    let hold = transition(&plan, ReservationAction::HoldPreview, None, plan_hash);
    history.record(&hold, false);
    assert_eq!(history.replay().unwrap(), plan.reservation);
    let before = history.entries.len();
    let start = transition(
        &plan,
        ReservationAction::StartPlan,
        Some(hold.operation_id),
        plan_hash,
    );
    history.record(&start, false);
    assert!(history.replay().is_err());
    history.entries.truncate(before);
    let approval = SubagentPlanApprovalV1::new(&plan, SubagentPlanDecision::Approve).unwrap();
    history.record(&approval, false);
    assert!(history.replay().is_err());
    history.entries.truncate(before);
    let consent = history.record(&approval, true);
    let start = transition(
        &plan,
        ReservationAction::StartPlan,
        Some(hold.operation_id),
        consent,
    );
    history.record(&start, false);
    assert_eq!(history.replay().unwrap(), plan.reservation);
    history.record(&start, false);
    assert!(history.replay().is_err());
}

#[test]
fn exactly_twenty_five_percent_does_not_require_threshold_consent_but_rechecks_consumption() {
    let mut history = History::new();
    let plan = history.plan(500_000);
    assert!(!plan.requires_signed_consent().unwrap());
    let plan_hash = history.record(&plan, false);
    let hold = transition(&plan, ReservationAction::HoldPreview, None, plan_hash);
    history.record(&hold, false);
    let before = history.entries.len();
    let start = transition(
        &plan,
        ReservationAction::StartPlan,
        Some(hold.operation_id),
        plan_hash,
    );
    history.record(&start, false);
    history.replay().unwrap();
    history.entries.truncate(before);
    history.append(
        AuditEventKind::ModelUsage,
        "{\"input_tokens\":1,\"output_tokens\":1,\"estimated_cost_microusd\":null}".into(),
        false,
    );
    history.record(&start, false);
    assert!(history.replay().is_err());
}

#[test]
fn a_failed_journal_is_poisoned_and_cannot_produce_a_verified_reservation_view() {
    let history = History::new();
    let mut journal = SubagentJournal::new(history.case.clone(), history.agent.actor()).unwrap();
    let mut invalid = history.entries[0].clone();
    invalid.payload.push(' ');
    assert!(journal.accept(&invalid, &history.verifier).is_err());
    assert!(
        journal
            .accept(&history.entries[0], &history.verifier)
            .is_err()
    );
    assert!(journal.outstanding().is_err());
}

fn branch_entry(
    history: &History,
    plan: &SubagentPlanV1,
    seq: u64,
    payload: irmind_app::subagents::SubagentBranchPayload,
    prev: SubagentDigest,
) -> irmind_app::subagents::SubagentBranchEntry {
    use irmind_app::subagents::{SubagentBranchBody, SubagentBranchEntry};
    SubagentBranchEntry::sign(
        SubagentBranchBody {
            case_id: plan.case_id.clone(),
            turn_id: plan.turn_id.clone(),
            task_id: plan.tasks[0].task_id,
            nonce: plan.tasks[0].nonce.clone(),
            seq,
            at: 10,
            payload,
            prev,
            public_key: SubagentDigest::parse(&hex(&history.agent.public_key())).unwrap(),
        },
        &history.agent,
    )
    .unwrap()
}

fn model_request_prefix(
    history: &mut History,
    plan: &SubagentPlanV1,
    plan_hash: SubagentDigest,
    start: &SubagentReservationV1,
) -> (
    SubagentReservationV1,
    irmind_app::subagents::SubagentBranchEntry,
    irmind_app::subagents::SubagentCheckpointV1,
) {
    use irmind_app::subagents::{BranchModelRequest, CheckedBranchChunk, SubagentBranchPayload};
    let reserve = SubagentReservationV1::prepare(
        plan,
        Some(plan.tasks[0].task_id),
        1,
        ReservationAction::ReserveRequest,
        ReservationPurpose::Model,
        ReservationTransition {
            amount: SubagentResources {
                tokens: 100,
                rounds: 1,
                ..SubagentResources::default()
            },
            parent_operation: Some(start.operation_id),
            cause_sha256: plan_hash,
            accounting_audit_sha256: None,
        },
    )
    .unwrap();
    history.record(&reserve, false);
    let request = branch_entry(
        history,
        plan,
        1,
        SubagentBranchPayload::ModelRequest(BranchModelRequest {
            call_id: "child_model_1".into(),
            model: "scripted".into(),
            messages_sha256: SubagentDigest::from_bytes([1; 32]),
            reservation_sha256: reserve.identity().unwrap(),
            round: 1,
            output_limit: 64,
        }),
        SubagentDigest::from_bytes([0; 32]),
    );
    let chunk = CheckedBranchChunk::from_entries(
        std::slice::from_ref(&request),
        &history.agent.public_key(),
        &history.verifier,
    )
    .unwrap();
    let first = chunk.checkpoint(None, vec![]).unwrap();
    history.record(&first, false);
    (reserve, request, first)
}

fn model_terminal_prefix(
    history: &mut History,
    plan: &SubagentPlanV1,
    reserve: &SubagentReservationV1,
    request: &irmind_app::subagents::SubagentBranchEntry,
    first: &irmind_app::subagents::SubagentCheckpointV1,
) -> (
    irmind_app::subagents::SubagentCheckpointV1,
    irmind_app::subagents::BranchTerminal,
    SubagentDigest,
) {
    use irmind_app::subagents::{
        BranchModelReply, BranchTerminal, CheckedBranchChunk, SubagentBranchPayload, SubagentStatus,
    };
    let accounting = history.append(
        AuditEventKind::ModelUsage,
        "{\"input_tokens\":10,\"output_tokens\":5,\"estimated_cost_microusd\":null}".into(),
        false,
    );
    let terminal = BranchTerminal {
        status: SubagentStatus::Completed,
        guarded_summary: "No evidence in this task.".into(),
        summary_sha256: SubagentDigest::from_bytes(sha256(b"No evidence in this task.")),
        sources: vec![],
        coverage: vec![],
        usage: SubagentResources {
            tokens: 15,
            rounds: 1,
            ..SubagentResources::default()
        },
        reservation_ids: vec![reserve.operation_id],
        pending_approvals: vec![],
    };
    let reply = branch_entry(
        history,
        plan,
        2,
        SubagentBranchPayload::ModelReply(BranchModelReply {
            call_id: "child_model_1".into(),
            guarded_text: terminal.guarded_summary.clone(),
            truncated: false,
            tool_calls: vec![],
            usage: Some(ModelUsage {
                input_tokens: 10,
                output_tokens: 5,
            }),
        }),
        request.hash,
    );
    let last = branch_entry(
        history,
        plan,
        3,
        SubagentBranchPayload::Terminal(terminal.clone()),
        reply.hash,
    );
    let chunk = CheckedBranchChunk::from_entries(
        &[reply, last],
        &history.agent.public_key(),
        &history.verifier,
    )
    .unwrap();
    let checkpoint = chunk
        .checkpoint(Some(first.identity().unwrap()), vec![])
        .unwrap();
    history.record(&checkpoint, false);
    (checkpoint, terminal, accounting)
}

#[test]
fn accounting_has_one_authoritative_charge_and_unknown_usage_stays_reserved() {
    use irmind_app::subagents::SubagentResultV1;
    let mut history = History::new();
    let plan = history.plan(100_000);
    let plan_hash = history.record(&plan, false);
    let hold = transition(&plan, ReservationAction::HoldPreview, None, plan_hash);
    history.record(&hold, false);
    let start = transition(
        &plan,
        ReservationAction::StartPlan,
        Some(hold.operation_id),
        plan_hash,
    );
    history.record(&start, false);
    let (reserve, request, first) = model_request_prefix(&mut history, &plan, plan_hash, &start);
    let (last, terminal, accounting) =
        model_terminal_prefix(&mut history, &plan, &reserve, &request, &first);
    let before_settle = history.entries.len();
    let settlement = |accounting| {
        SubagentReservationV1::prepare(
            &plan,
            Some(plan.tasks[0].task_id),
            1,
            ReservationAction::SettleRequest,
            ReservationPurpose::Model,
            ReservationTransition {
                amount: terminal.usage,
                parent_operation: Some(reserve.operation_id),
                cause_sha256: last.identity().unwrap(),
                accounting_audit_sha256: accounting,
            },
        )
        .unwrap()
    };
    history.record(
        &settlement(Some(SubagentDigest::from_bytes([9; 32]))),
        false,
    );
    assert!(history.replay().is_err());
    history.entries.truncate(before_settle);
    history.record(&settlement(Some(accounting)), false);
    assert_eq!(
        history.replay().unwrap(),
        plan.reservation.checked_sub(terminal.usage).unwrap()
    );
    history.record(&settlement(Some(accounting)), false);
    assert!(history.replay().is_err());
    history.entries.truncate(before_settle);
    history.record(&settlement(None), false);
    assert_eq!(history.replay().unwrap(), plan.reservation);
    history.record(
        &SubagentResultV1::from_terminal(&last, &terminal).unwrap(),
        false,
    );
    let mut release = transition(
        &plan,
        ReservationAction::ReleasePlan,
        Some(start.operation_id),
        last.identity().unwrap(),
    );
    release.amount = plan.reservation.checked_sub(reserve.amount).unwrap();
    history.record(&release, false);
    assert_eq!(history.replay().unwrap(), reserve.amount);
}

#[test]
fn child_dispatch_attribution_matches_the_approved_canonical_vector() {
    let bytes = include_bytes!(
        "../../../../../docs/development/subagent-format-vectors/dispatch-attribution.json"
    );
    let mut value: irmind_app::subagents::TaskDispatchAttribution =
        serde_json::from_slice(bytes).unwrap();
    assert_eq!(value.canonical().unwrap(), bytes);
    value.call_id = "invalid call".into();
    assert!(value.canonical().is_err());
}
