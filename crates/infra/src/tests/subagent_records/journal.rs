mod broker;
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
    fn journal(&self) -> Result<SubagentJournal, AppError> {
        let mut journal = SubagentJournal::new(self.case.clone(), self.agent.actor()).unwrap();
        for entry in &self.entries {
            journal.accept(entry, &self.verifier)?;
        }
        Ok(journal)
    }
    fn replay(&self) -> Result<SubagentResources, AppError> {
        self.journal()?
            .outstanding()
            .map_err(|_| AppError::InvalidChain(0))
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
    Vec<irmind_app::subagents::SubagentBranchEntry>,
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
    let entries = vec![reply, last];
    let chunk =
        CheckedBranchChunk::from_entries(&entries, &history.agent.public_key(), &history.verifier)
            .unwrap();
    let checkpoint = chunk
        .checkpoint(Some(first.identity().unwrap()), vec![])
        .unwrap();
    history.record(&checkpoint, false);
    (checkpoint, terminal, accounting, entries)
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
    let (last, terminal, accounting, _) =
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
    assert_eq!(
        history.replay().unwrap(),
        SubagentResources {
            rounds: 0,
            ..plan.reservation
        }
    );
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
    assert_eq!(
        history.replay().unwrap(),
        SubagentResources {
            rounds: 0,
            ..reserve.amount
        }
    );
}

fn completed_child_with_coordination() -> (
    History,
    SubagentPlanV1,
    SubagentReservationV1,
    irmind_app::subagents::SubagentCheckpointV1,
    irmind_app::subagents::BranchTerminal,
) {
    use irmind_app::subagents::SubagentResultV1;
    let mut history = History::new();
    let mut plan = history.plan(100_000);
    plan.coordination = SubagentResources {
        tokens: 100,
        rounds: 1,
        ..SubagentResources::default()
    };
    plan.reservation = plan.reservation.checked_add(plan.coordination).unwrap();
    plan.validate().unwrap();
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
    let (last, terminal, accounting, _) =
        model_terminal_prefix(&mut history, &plan, &reserve, &request, &first);
    let settled = SubagentReservationV1::prepare(
        &plan,
        Some(plan.tasks[0].task_id),
        1,
        ReservationAction::SettleRequest,
        ReservationPurpose::Model,
        ReservationTransition {
            amount: terminal.usage,
            parent_operation: Some(reserve.operation_id),
            cause_sha256: last.identity().unwrap(),
            accounting_audit_sha256: Some(accounting),
        },
    )
    .unwrap();
    history.record(&settled, false);
    history.record(
        &SubagentResultV1::from_terminal(&last, &terminal).unwrap(),
        false,
    );
    (history, plan, start, last, terminal)
}

#[test]
fn coordination_summary_uses_its_own_slice_without_double_charging_parent_rounds() {
    let (mut history, plan, start, last, terminal) = completed_child_with_coordination();
    let summary = SubagentReservationV1::prepare(
        &plan,
        None,
        1,
        ReservationAction::ReserveRequest,
        ReservationPurpose::Model,
        ReservationTransition {
            amount: plan.coordination,
            parent_operation: Some(start.operation_id),
            cause_sha256: last.identity().unwrap(),
            accounting_audit_sha256: None,
        },
    )
    .unwrap();
    history.record(&summary, false);
    history.append(
        AuditEventKind::ModelRequest,
        "summary without tools".into(),
        true,
    );
    let usage = SubagentResources {
        tokens: 15,
        rounds: 1,
        ..SubagentResources::default()
    };
    let before_usage = history.entries.len();
    let settle_summary = |history: &mut History, analyst: bool| {
        let accounting = history.append(
            AuditEventKind::ModelUsage,
            "{\"input_tokens\":10,\"output_tokens\":5,\"estimated_cost_microusd\":null}".into(),
            analyst,
        );
        let settlement = SubagentReservationV1::prepare(
            &plan,
            None,
            1,
            ReservationAction::SettleRequest,
            ReservationPurpose::Model,
            ReservationTransition {
                amount: usage,
                parent_operation: Some(summary.operation_id),
                cause_sha256: last.identity().unwrap(),
                accounting_audit_sha256: Some(accounting),
            },
        )
        .unwrap();
        history.record(&settlement, false);
    };
    settle_summary(&mut history, false);
    assert!(history.replay().is_err()); // Child usage cannot pay for a parent summary.
    history.entries.truncate(before_usage);
    settle_summary(&mut history, true);
    let spent = terminal.usage.checked_add(usage).unwrap();
    assert_eq!(
        history.replay().unwrap(),
        plan.reservation.checked_sub(spent).unwrap()
    );
    let mut release = transition(
        &plan,
        ReservationAction::ReleasePlan,
        Some(start.operation_id),
        last.identity().unwrap(),
    );
    release.amount = plan.reservation.checked_sub(spent).unwrap();
    history.record(&release, false);
    assert_eq!(history.replay().unwrap(), SubagentResources::default());
    check_next_coordination_turn(&mut history, &plan, spent);
}

fn check_next_coordination_turn(
    history: &mut History,
    plan: &SubagentPlanV1,
    spent: SubagentResources,
) {
    let mut task = plan.tasks[0].clone();
    task.nonce = "00000000-0000-0000-0000-000000000003".into();
    let mut context = SubagentPlanContext {
        parent_checkpoint_sha256: SubagentDigest::from_bytes(history.entries.last().unwrap().hash),
        budget_checkpoint_sha256: SubagentDigest::from_bytes(history.entries[0].hash),
        policy: plan.policy.clone(),
        case_limits: plan.case_limits,
        usage: spent,
        prior_reserved: SubagentResources::default(),
    };
    context.usage.rounds = 2; // One parent request and one child request, counted once.
    let next = SubagentPlanV1::prepare(
        &history.case,
        &plan.turn_id,
        2,
        context,
        vec![task],
        SubagentResources::default(),
        plan.deadline_at,
    )
    .unwrap();
    let next_hash = history.record(&next, false);
    let hold = transition(&next, ReservationAction::HoldPreview, None, next_hash);
    history.record(&hold, false);
    assert_eq!(history.replay().unwrap(), next.reservation);
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

#[test]
fn subagent_round_allowance_includes_parent_requests_and_compaction() {
    let mut history = History::new();
    history.append(
        AuditEventKind::Prompt,
        "Synthetic analyst question".into(),
        true,
    );
    history.append(
        AuditEventKind::ModelRequest,
        "round=1;messages=2".into(),
        true,
    );
    history.append(
        AuditEventKind::ModelRequest,
        "conversation compaction".into(),
        true,
    );
    let mut plan = history.plan(100_000);
    let before = history.entries.len();
    history.record(&plan, false);
    assert!(history.replay().is_err());
    history.entries.truncate(before);
    plan.usage.rounds = 2;
    plan.remaining.rounds -= 2;
    plan.validate().unwrap();
    let plan_hash = history.record(&plan, false);
    let hold = transition(&plan, ReservationAction::HoldPreview, None, plan_hash);
    history.record(&hold, false);
    history.replay().unwrap();
    history.append(
        AuditEventKind::Prompt,
        "Reset the round count".into(),
        false,
    );
    assert!(history.replay().is_err());
}

fn completed_model_history() -> (
    History,
    Vec<irmind_app::subagents::CheckedBranchChunk>,
    usize,
    irmind_app::subagents::SubagentCheckpointV1,
    irmind_app::subagents::BranchTerminal,
) {
    use irmind_app::subagents::{CheckedBranchChunk, SubagentResultV1};
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
    let first_chunk = CheckedBranchChunk::from_entries(
        std::slice::from_ref(&request),
        &history.agent.public_key(),
        &history.verifier,
    )
    .unwrap();
    let (last, terminal, accounting, entries) =
        model_terminal_prefix(&mut history, &plan, &reserve, &request, &first);
    let last_chunk =
        CheckedBranchChunk::from_entries(&entries, &history.agent.public_key(), &history.verifier)
            .unwrap();
    let settled = SubagentReservationV1::prepare(
        &plan,
        Some(plan.tasks[0].task_id),
        1,
        ReservationAction::SettleRequest,
        ReservationPurpose::Model,
        ReservationTransition {
            amount: terminal.usage,
            parent_operation: Some(reserve.operation_id),
            cause_sha256: last.identity().unwrap(),
            accounting_audit_sha256: Some(accounting),
        },
    )
    .unwrap();
    history.record(&settled, false);
    let before_result = history.entries.len();
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
    release.amount = plan.reservation.checked_sub(terminal.usage).unwrap();
    history.record(&release, false);
    assert_eq!(history.replay().unwrap(), SubagentResources::default());
    (
        history,
        vec![first_chunk, last_chunk],
        before_result,
        last,
        terminal,
    )
}

fn supply_material<'a>(
    journal: &'a SubagentJournal,
    history: &History,
    chunks: &[irmind_app::subagents::CheckedBranchChunk],
) -> Result<
    irmind_app::subagents::BranchMaterialVerifier<'a>,
    irmind_app::subagents::SubagentRecordError,
> {
    let mut material = irmind_app::subagents::BranchMaterialVerifier::new(journal)?;
    let mut skills = irmind_app::SkillReceiptVerifier::default();
    for chunk in chunks {
        let descriptor = material.next_descriptor()?.unwrap();
        material.accept(
            &descriptor,
            chunk.bytes(),
            &history.verifier,
            &mut skills,
            &TomlSkillCompiler,
        )?;
    }
    Ok(material)
}

#[test]
fn subagent_material_rejects_missing_extra_and_noncanonical_descriptors_without_recovery() {
    use irmind_app::subagents::BranchMaterialVerifier;
    let (history, chunks, _, _, _) = completed_model_history();
    let journal = history.journal().unwrap();
    assert_eq!(BranchMaterialVerifier::new(&journal).unwrap().count(), 2);
    assert!(
        BranchMaterialVerifier::new(&journal)
            .unwrap()
            .finish()
            .is_err()
    );
    let mut material = BranchMaterialVerifier::new(&journal).unwrap();
    let descriptor = material.next_descriptor().unwrap().unwrap();
    let mut wrong = descriptor.clone();
    wrong.push(b' ');
    let mut skills = irmind_app::SkillReceiptVerifier::default();
    assert!(
        material
            .accept(
                &wrong,
                chunks[0].bytes(),
                &history.verifier,
                &mut skills,
                &TomlSkillCompiler
            )
            .is_err()
    );
    assert!(
        material
            .accept(
                &descriptor,
                chunks[0].bytes(),
                &history.verifier,
                &mut skills,
                &TomlSkillCompiler
            )
            .is_err()
    );
    assert!(material.next_reference().is_err());
    assert!(material.finish().is_err());
    supply_material(&journal, &history, &chunks)
        .unwrap()
        .finish()
        .unwrap();
    let mut extra = supply_material(&journal, &history, &chunks).unwrap();
    assert!(extra.next_reference().unwrap().is_none());
    assert!(
        extra
            .accept(
                b"{}",
                chunks[0].bytes(),
                &history.verifier,
                &mut skills,
                &TomlSkillCompiler
            )
            .is_err()
    );
    assert!(extra.finish().is_err());
}

#[test]
fn subagent_material_verifies_the_case_local_chunk_store_and_rejects_missing_material() {
    use irmind_app::subagents::SubagentBranchStore;
    let (history, chunks, _, _, _) = completed_model_history();
    let journal = history.journal().unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let cancel = CancellationToken::new();
    for chunk in &chunks {
        store
            .publish(store.stage(&history.case, chunk, &cancel).unwrap())
            .unwrap();
    }
    let mut skills = irmind_app::SkillReceiptVerifier::default();
    journal
        .verify_stored_branches(
            &store,
            &history.verifier,
            &mut skills,
            &TomlSkillCompiler,
            &cancel,
        )
        .unwrap();
    let path = root
        .path()
        .join("parquet")
        .join(history.case.as_str())
        .join(format!(
            "branches/{}.json",
            hex(chunks[1].hash().as_bytes())
        ));
    fs::remove_file(path).unwrap();
    assert!(
        journal
            .verify_stored_branches(
                &store,
                &history.verifier,
                &mut skills,
                &TomlSkillCompiler,
                &cancel
            )
            .is_err()
    );
}

#[test]
fn subagent_main_result_must_repeat_the_committed_terminal_exactly() {
    use irmind_app::subagents::SubagentResultV1;
    let (mut history, chunks, before_result, checkpoint, mut terminal) = completed_model_history();
    history.entries.truncate(before_result);
    terminal.guarded_summary = "A different summary.".into();
    terminal.summary_sha256 =
        SubagentDigest::from_bytes(sha256(terminal.guarded_summary.as_bytes()));
    history.record(
        &SubagentResultV1::from_terminal(&checkpoint, &terminal).unwrap(),
        false,
    );
    let journal = history.journal().unwrap();
    assert!(
        supply_material(&journal, &history, &chunks)
            .and_then(irmind_app::subagents::BranchMaterialVerifier::finish)
            .is_err()
    );
}

struct NoTaskQueries;
impl irmind_app::subagents::TaskEvidenceQueries for NoTaskQueries {
    fn execute(
        &self,
        _: &irmind_app::subagents::VerifiedTaskQueryView,
        _: irmind_app::subagents::TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<irmind_app::subagents::TaskEvidenceResult, AppError> {
        Err(AppError::InvalidChain(0))
    }
}
struct NoPlanInteraction;
impl irmind_app::subagents::AnalystPlanInteraction for NoPlanInteraction {
    fn review<'a>(
        &'a self,
        _: &'a irmind_app::subagents::SafePlanPreview,
        _: &'a CancellationToken,
    ) -> irmind_app::subagents::PortFuture<'a, irmind_app::subagents::AnalystPlanChoice> {
        Box::pin(async { Err(AppError::InvalidChain(0)) })
    }
}
fn stored_history_engine(
    root: &std::path::Path,
    history: &History,
    chunks: &[irmind_app::subagents::CheckedBranchChunk],
) -> (Arc<LocalStore>, Engine<'static>) {
    use irmind_app::{
        CaseMutation, SkillServices,
        subagents::{SubagentBranchStore, SubagentPorts},
    };
    let store = Arc::new(LocalStore::open(root).unwrap());
    store
        .transact(
            &history.entries[0],
            CaseMutation::Create(Case {
                id: history.case.clone(),
                title: "Contract synthetic case".into(),
                severity: Severity::Medium,
                scope: "local".into(),
                sealed: false,
            }),
        )
        .unwrap();
    if history.entries.len() > 1 {
        store.append_batch(&history.entries[1..]).unwrap();
    }
    for chunk in chunks {
        store
            .parquet
            .publish(
                store
                    .parquet
                    .stage(&history.case, chunk, &CancellationToken::new())
                    .unwrap(),
            )
            .unwrap();
    }
    let agent = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[43; 32]),
        actor: history.agent.actor(),
    });
    let analyst = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[42; 32]),
        actor: Actor::Analyst,
    });
    let services = SkillServices::new(
        Arc::new(crate::FileSkillPackageStore::new(root)),
        Arc::new(TomlSkillCompiler),
        agent,
        Vec::new(),
    )
    .unwrap();
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(analyst, Arc::new(history.verifier.clone())),
            Arc::new(MandatoryGuard::new().unwrap()),
        )
        .with_subagents(SubagentPorts {
            branches: Arc::new(ParquetStore::open(root).unwrap()),
            queries: Arc::new(NoTaskQueries),
            analyst: Arc::new(NoPlanInteraction),
        }),
        ExecutionMode::Attended,
        Arc::new(irmind_testkit::FixedClock::new(10)),
    )
    .unwrap()
    .with_skills(services)
    .unwrap();
    (store, engine)
}

#[test]
fn subagent_case_verification_seal_and_offline_v8_keep_every_committed_chunk() {
    let (history, chunks, _, _, _) = completed_model_history();
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = stored_history_engine(root.path(), &history, &chunks);
    engine.verify(&history.case).unwrap();
    engine.seal(&history.case).unwrap();
    let output = root.path().join("branch-export.irmind");
    CaseExporter::export_case(
        store.as_ref(),
        &history.case,
        &output,
        &CancellationToken::new(),
    )
    .unwrap();
    let fingerprint = hex(&sha256(&history.analyst.public_key()));
    verify_export_expected(&output, Some(&fingerprint)).unwrap();
    let bytes = fs::read(&output).unwrap();
    assert_eq!(
        bytes,
        include_bytes!("../../../../../fuzz/seeds/export/valid-v8-subagents.irmind")
    );
    let chunk = chunks[1].bytes();
    let position = bytes
        .windows(chunk.len())
        .position(|candidate| candidate == chunk)
        .unwrap();
    let mut tampered = bytes.clone();
    tampered[position + chunk.len() / 2] ^= 1;
    let broken = root.path().join("changed.irmind");
    fs::write(&broken, tampered).unwrap();
    assert!(verify_export_expected(&broken, Some(&fingerprint)).is_err());
    let path = root
        .path()
        .join("parquet")
        .join(history.case.as_str())
        .join(format!(
            "branches/{}.json",
            hex(chunks[1].hash().as_bytes())
        ));
    fs::remove_file(path).unwrap();
    assert!(engine.verify(&history.case).is_err());
    let failed = root.path().join("missing.irmind");
    assert!(
        CaseExporter::export_case(
            store.as_ref(),
            &history.case,
            &failed,
            &CancellationToken::new()
        )
        .is_err()
    );
    assert!(!failed.exists());
    // The completed export is independent of the local branch store.
    verify_export_expected(&output, Some(&fingerprint)).unwrap();
}

#[test]
fn subagent_open_plan_prevents_sealing_and_a_new_root_turn() {
    let mut history = History::new();
    let plan = history.plan(100_000);
    let plan_hash = history.record(&plan, false);
    history.record(
        &transition(&plan, ReservationAction::HoldPreview, None, plan_hash),
        false,
    );
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = stored_history_engine(root.path(), &history, &[]);
    assert!(engine.seal(&history.case).is_err());
    history.append(AuditEventKind::Prompt, "a second turn".into(), true);
    assert!(history.replay().is_err());
}
