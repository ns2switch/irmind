use super::{EngineEvent, EngineEventKind, EventCursor, invalid, position};
use crate::subagents::{
    SubagentBranchEntry, SubagentBranchPayload, SubagentCheckpointV1, SubagentPlanApprovalV1,
    SubagentPlanV1, SubagentRecord, SubagentReservationV1, SubagentResultV1,
};
use crate::{AppError, AuditEventKind, Engine, SignedEntry};

pub(super) fn main(
    engine: &Engine<'_>,
    entry: &SignedEntry,
) -> Result<Option<EngineEvent>, AppError> {
    let (kind, text, task, turn, usage) = match entry.kind {
        AuditEventKind::SubagentPlanV1 => {
            let plan: SubagentPlanV1 = decode(entry)?;
            let kind = if plan.requires_signed_consent().map_err(|_| invalid())?
                || engine.confirm_all_subagent_plans()?
            {
                EngineEventKind::ConsentRequired
            } else {
                EngineEventKind::PlanPreview
            };
            (
                kind,
                format!(
                    "Plan {}: {} tasks; reserved {} tokens and {} calls",
                    crate::hex(plan.plan_id.as_bytes()),
                    plan.tasks.len(),
                    plan.reservation.tokens,
                    plan.reservation.calls
                ),
                None,
                Some(plan.turn_id),
                Some(plan.reservation),
            )
        }
        AuditEventKind::SubagentPlanApprovalV1 => {
            let approval: SubagentPlanApprovalV1 = decode(entry)?;
            (
                EngineEventKind::Status,
                format!("Analyst plan decision: {:?}", approval.decision),
                None,
                None,
                None,
            )
        }
        AuditEventKind::SubagentReservationV1 => {
            let reservation: SubagentReservationV1 = decode(entry)?;
            (
                EngineEventKind::Budget,
                format!("{:?} {:?}", reservation.action, reservation.purpose),
                reservation.task_id,
                None,
                Some(reservation.amount),
            )
        }
        AuditEventKind::SubagentCheckpointV1 => {
            let checkpoint: SubagentCheckpointV1 = decode(entry)?;
            (
                EngineEventKind::Checkpoint,
                format!("Committed branch {}–{}", checkpoint.first, checkpoint.last),
                Some(checkpoint.task_id),
                None,
                None,
            )
        }
        AuditEventKind::SubagentResultV1 => {
            let result: SubagentResultV1 = decode(entry)?;
            (
                EngineEventKind::Status,
                format!("{:?}: {}", result.status, result.guarded_summary),
                Some(result.task_id),
                None,
                Some(result.usage),
            )
        }
        _ => return Ok(None),
    };
    let mut event = build(engine, entry, 64, kind, &text)?;
    event.task_id = task;
    if matches!(
        kind,
        EngineEventKind::PlanPreview | EngineEventKind::ConsentRequired
    ) {
        event.plan_id = Some(decode::<SubagentPlanV1>(entry)?.plan_id);
    }
    event.turn_id = turn;
    event.usage = usage;
    Ok(Some(event))
}

pub(super) fn branch(
    engine: &Engine<'_>,
    main: &SignedEntry,
    item: &SubagentBranchEntry,
    index: usize,
) -> Result<EngineEvent, AppError> {
    let (kind, text) = match &item.body.payload {
        SubagentBranchPayload::ModelRequest(value) => (
            EngineEventKind::Round,
            format!("Round {} · {}", value.round, value.model),
        ),
        SubagentBranchPayload::ModelReply(value) => {
            (EngineEventKind::Message, value.guarded_text.clone())
        }
        SubagentBranchPayload::ToolProposal(value) => (
            EngineEventKind::ToolProposal,
            format!(
                "{}({})",
                value.tool,
                serde_json::to_string(&value.arguments).map_err(|_| invalid())?
            ),
        ),
        SubagentBranchPayload::ToolResult(value) => {
            (EngineEventKind::ToolResult, value.guarded_text.clone())
        }
        SubagentBranchPayload::SkillLoad(_) => {
            (EngineEventKind::Message, "Methodology load recorded".into())
        }
        SubagentBranchPayload::Compaction(value) => {
            (EngineEventKind::Message, value.guarded_text.clone())
        }
        SubagentBranchPayload::BudgetNotice(value) => (
            EngineEventKind::Budget,
            format!(
                "{:?}: {} of {}",
                value.resource, value.consumed, value.limit
            ),
        ),
        SubagentBranchPayload::Terminal(value) => (
            EngineEventKind::Status,
            format!("{:?}: {}", value.status, value.guarded_summary),
        ),
    };
    let mut event = build(engine, main, index, kind, &text)?;
    event.task_id = Some(item.body.task_id);
    event.turn_id = Some(item.body.turn_id.clone());
    if let SubagentBranchPayload::ModelReply(reply) = &item.body.payload {
        event.model_reply = true;
        event.model_usage = reply.usage;
        event.estimated_cost_microusd = reply
            .usage
            .map(|usage| engine.usage_cost(usage))
            .transpose()?
            .flatten();
    }
    Ok(event)
}
fn build(
    engine: &Engine<'_>,
    entry: &SignedEntry,
    slot: usize,
    kind: EngineEventKind,
    text: &str,
) -> Result<EngineEvent, AppError> {
    let mut safe = engine.guard.screen(text)?.text;
    let clipped = safe.len() > 16 * 1024;
    safe.truncate(safe.floor_char_boundary(safe.len().min(16 * 1024)));
    let session = engine.subagent_runtime.session;
    Ok(EngineEvent {
        version: 1,
        session_id: session,
        cursor: EventCursor {
            session,
            position: position(entry.seq, slot)?,
            case: crate::sha256(entry.case_id.as_bytes()),
        },
        case_id: crate::CaseId::parse(&entry.case_id).map_err(|_| invalid())?,
        turn_id: None,
        task_id: None,
        plan_id: None,
        task_type: None,
        objective: None,
        kind,
        payload: safe,
        usage: None,
        model_reply: false,
        model_usage: None,
        estimated_cost_microusd: None,
        clipped,
    })
}
pub(super) fn decode<T: SubagentRecord>(entry: &SignedEntry) -> Result<T, AppError> {
    crate::subagents::journal::decode_entry(entry).map_err(|_| AppError::InvalidChain(entry.seq))
}
