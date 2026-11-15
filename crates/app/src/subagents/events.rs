//! Read-only projections of durable engine records; cursors grant no authority.
use super::{SubagentDigest, SubagentResources};
use crate::{AppError, CancellationToken, CaseId, Engine};
mod projection;
mod subscription;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventCursor {
    session: uuid::Uuid,
    position: u64,
    case: [u8; 32],
}
impl EventCursor {
    pub const fn session_id(self) -> uuid::Uuid {
        self.session
    }
    pub const fn position(self) -> u64 {
        self.position
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineEventKind {
    PlanPreview,
    ConsentRequired,
    Message,
    Round,
    ToolProposal,
    ToolResult,
    Approval,
    Status,
    Coverage,
    Budget,
    Checkpoint,
}
#[derive(Clone, Debug)]
pub struct EngineEvent {
    pub version: u8,
    pub session_id: uuid::Uuid,
    pub cursor: EventCursor,
    pub case_id: CaseId,
    pub turn_id: Option<String>,
    pub task_id: Option<SubagentDigest>,
    pub kind: EngineEventKind,
    /// Guarded presentation text, never a request or an approval capability.
    pub payload: String,
    pub usage: Option<SubagentResources>,
    pub clipped: bool,
}
pub struct EngineEventBatch {
    pub events: Vec<EngineEvent>,
    pub next: EventCursor,
    pub more: bool,
}
pub trait EngineEventSubscription: Send {
    fn poll(
        &mut self,
        cursor: EventCursor,
        max: u16,
        cancel: &CancellationToken,
    ) -> Result<EngineEventBatch, AppError>;
}
impl Engine<'_> {
    /// Reconnect replays committed state. It never reconstructs an execution lease.
    pub fn subscribe_case_events(
        &self,
        case: &CaseId,
    ) -> Result<(EventCursor, Box<dyn EngineEventSubscription>), AppError> {
        self.repo.get_case(case)?;
        if self.subagents.is_none() || self.skills.is_none() {
            return Err(invalid());
        }
        let cursor = EventCursor {
            session: self.subagent_runtime.session,
            position: 0,
            case: crate::sha256(case.as_str().as_bytes()),
        };
        Ok((
            cursor,
            Box::new(subscription::Subscription::new(
                self.local_handle(),
                case.clone(),
            )),
        ))
    }
}
fn invalid() -> AppError {
    AppError::Policy(
        "The engine event cursor is invalid or its committed state is unavailable".into(),
    )
}
fn position(seq: u64, slot: usize) -> Result<u64, AppError> {
    seq.checked_mul(65)
        .and_then(|seq| seq.checked_add(slot as u64))
        .ok_or_else(invalid)
}
