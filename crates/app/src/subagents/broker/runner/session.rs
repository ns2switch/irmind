use super::{invalid, messages};
use crate::subagents::{
    BranchTerminal, SubagentCheckpointV1, SubagentDigest, SubagentRecord, SubagentResources,
    SubagentSourceRef, SubagentStatus, SubagentTaskSpec,
};
use crate::{AppError, CompletionMessage};
use std::collections::BTreeSet;

pub(super) struct TaskSession {
    pub messages: Vec<CompletionMessage>,
    pub skills: crate::skills::runtime::SkillTurn,
    pub method: Option<crate::SkillSnapshotId>,
    pub partial: bool,
    pub checkpoint: Option<SubagentCheckpointV1>,
    pub previous: SubagentDigest,
    pub seq: u64,
    pub round: u64,
    pub call: u64,
    pub usage: SubagentResources,
    pub reservations: BTreeSet<SubagentDigest>,
    pub sources: BTreeSet<SubagentSourceRef>,
    pub summary: String,
    pub coverage: BTreeSet<String>,
}
impl TaskSession {
    pub(super) fn new(
        started: &super::StartedSubagentPlan,
        task: &SubagentTaskSpec,
        objective: &str,
    ) -> Result<Self, AppError> {
        let nonce = uuid::Uuid::parse_str(&task.nonce).map_err(|_| invalid())?;
        Ok(Self {
            messages: messages::initial(objective, &nonce, task.source_set_sha256),
            skills: crate::skills::runtime::SkillTurn {
                budget: started.skill_budget.clone(),
                active: None,
                read_limit: 16 * 1024,
            },
            method: None,
            partial: false,
            checkpoint: None,
            previous: SubagentDigest::from_bytes([0; 32]),
            seq: 0,
            round: 0,
            call: 0,
            usage: SubagentResources::default(),
            reservations: BTreeSet::new(),
            sources: BTreeSet::new(),
            summary: String::new(),
            coverage: BTreeSet::new(),
        })
    }
    pub(super) fn checkpoint_id(&self) -> Result<Option<SubagentDigest>, AppError> {
        self.checkpoint
            .as_ref()
            .map(SubagentRecord::identity)
            .transpose()
            .map_err(|_| invalid())
    }
    pub(super) fn terminal(&self, status: SubagentStatus) -> BranchTerminal {
        BranchTerminal {
            status: if status == SubagentStatus::Completed && self.partial {
                SubagentStatus::Partial
            } else {
                status
            },
            guarded_summary: self.summary.clone(),
            summary_sha256: SubagentDigest::from_bytes(crate::sha256(self.summary.as_bytes())),
            sources: self.sources.iter().copied().collect(),
            coverage: self.coverage.iter().cloned().collect(),
            usage: self.usage,
            reservation_ids: self.reservations.iter().copied().collect(),
            pending_approvals: vec![],
        }
    }
    pub(super) fn tool_message(
        &mut self,
        task: &SubagentTaskSpec,
        call: &str,
        text: &str,
    ) -> Result<(), AppError> {
        let nonce = uuid::Uuid::parse_str(&task.nonce).map_err(|_| invalid())?;
        self.messages.push(CompletionMessage::tool_result(
            call.into(),
            format!(
                "<UNTRUSTED_{nonce}>\n{}\n</UNTRUSTED_{nonce}>",
                crate::isolate_untrusted(text, &nonce)
            ),
        ));
        Ok(())
    }
}
