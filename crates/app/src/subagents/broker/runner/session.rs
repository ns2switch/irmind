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
    pub continuations: u8,
    pub continuing: bool,
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
    pub pending: Option<super::tools::approvals::PendingChildTool>,
    pub queued: std::collections::VecDeque<crate::subagents::BranchToolCall>,
    pub observed: std::collections::BTreeMap<String, super::tools::indicators::ObservedIndicator>,
    pub edited_calls: u8,
    pub edited_ids: std::collections::BTreeMap<String, String>,
    pub pending_approvals: Vec<SubagentDigest>,
    call_ids: BTreeSet<String>,
}
impl TaskSession {
    pub(super) fn transfer_fits(
        &mut self,
        call: &crate::subagents::BranchToolCall,
        limit: u64,
    ) -> bool {
        if call.tool != crate::Tool::ObjectRead.as_str() {
            return true;
        }
        let Some(bytes) = call
            .arguments
            .get("max_bytes")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return true;
        };
        let remaining = limit.saturating_sub(self.usage.cloud_bytes);
        if bytes <= remaining {
            return true;
        }
        self.partial = true;
        self.coverage.insert(format!("The task cloud-byte budget cannot reserve {bytes} bytes; {remaining} remain. No transfer started. Review the case allocation with /budget and propose a new bounded plan."));
        false
    }
    pub(super) fn accept_call_id(&mut self, id: &str) -> bool {
        if self.call_ids.insert(id.to_owned()) {
            true
        } else {
            self.partial = true;
            self.coverage.insert("The provider repeated a tool-call identifier; the task stopped without repeating the effect.".into());
            false
        }
    }
    pub(super) fn queue_edited_call(
        &mut self,
        call: &crate::subagents::BranchToolCall,
        args: std::collections::BTreeMap<String, String>,
    ) -> bool {
        if self.edited_calls >= 16 {
            self.coverage.insert(
                "The task request editing limit was reached; no further lookup was executed."
                    .into(),
            );
            return false;
        }
        self.edited_calls += 1;
        let id = format!(
            "edited_{}_{}",
            &crate::hex(&crate::sha256(call.id.as_bytes()))[..16],
            self.seq
        );
        let original = self
            .edited_ids
            .remove(&call.id)
            .unwrap_or_else(|| call.id.clone());
        self.edited_ids.insert(id.clone(), original);
        self.queued.push_front(crate::subagents::BranchToolCall {
            id,
            tool: call.tool.clone(),
            arguments: args,
        });
        true
    }
    pub(super) fn new(
        started: &super::StartedSubagentPlan,
        task: &SubagentTaskSpec,
        objective: &str,
    ) -> Result<Self, AppError> {
        let nonce = uuid::Uuid::parse_str(&task.nonce).map_err(|_| invalid())?;
        let mut initial = messages::initial(objective, &nonce, task.source_set_sha256);
        initial[0].content.push(' ');
        initial[0].content.push_str(messages::role(started, task)?);
        Ok(Self {
            messages: initial,
            skills: crate::skills::runtime::SkillTurn {
                budget: started.skill_budget.clone(),
                active: None,
                read_limit: 16 * 1024,
            },
            method: None,
            partial: false,
            continuations: 0,
            continuing: false,
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
            pending: None,
            queued: std::collections::VecDeque::new(),
            observed: std::collections::BTreeMap::new(),
            edited_calls: 0,
            edited_ids: std::collections::BTreeMap::new(),
            pending_approvals: vec![],
            call_ids: BTreeSet::new(),
        })
    }
    pub(super) fn record_model_result(
        &mut self,
        usage: SubagentResources,
        summary: String,
        truncated: bool,
    ) -> Result<(), AppError> {
        self.usage = self.usage.checked_add_usage(usage).map_err(|_| invalid())?;
        self.summary = summary;
        if truncated {
            self.partial = true;
            self.coverage
                .insert("The provider truncated a model reply.".into());
        }
        Ok(())
    }
    pub(super) fn checkpoint_id(&self) -> Result<Option<SubagentDigest>, AppError> {
        self.checkpoint
            .as_ref()
            .map(SubagentRecord::identity)
            .transpose()
            .map_err(|_| invalid())
    }
    pub(super) fn retain_sources(&mut self, sources: Vec<SubagentSourceRef>) {
        for source in sources {
            // References are a bounded summary, not the complete branch inventory.
            // Leave room in the 256 KiB terminal frame for reservations and text.
            if self.sources.len() < 1024 || self.sources.contains(&source) {
                self.sources.insert(source);
            } else {
                self.partial = true;
                self.coverage.insert(
                    "The terminal reference summary was bounded; complete references remain in the task branch.".into(),
                );
            }
        }
    }
    pub(super) fn terminal(&self, status: SubagentStatus) -> BranchTerminal {
        bounded_terminal(BranchTerminal {
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
            pending_approvals: self.pending_approvals.clone(),
        })
    }
    pub(super) fn tool_message(
        &mut self,
        task: &SubagentTaskSpec,
        call: &str,
        text: &str,
    ) -> Result<(), AppError> {
        let nonce = uuid::Uuid::parse_str(&task.nonce).map_err(|_| invalid())?;
        self.messages.push(CompletionMessage::tool_result(
            self.edited_ids.remove(call).unwrap_or_else(|| call.into()),
            format!(
                "<UNTRUSTED_{nonce}>\n{}\n</UNTRUSTED_{nonce}>",
                crate::isolate_untrusted(text, &nonce)
            ),
        ));
        Ok(())
    }
}

fn bounded_terminal(mut terminal: BranchTerminal) -> BranchTerminal {
    // The complete reference list stays in the signed branch results. Keep
    // headroom for the outer entry and signature without discarding accounting.
    let mut clipped = false;
    while !terminal.sources.is_empty()
        && serde_json::to_vec(&terminal).map_or(true, |bytes| bytes.len() > 254 * 1024)
    {
        terminal.sources.truncate(terminal.sources.len() / 2);
        if !clipped {
            terminal.coverage.push("The terminal reference summary was bounded; complete references remain in the task branch.".into());
            if terminal.status == SubagentStatus::Completed {
                terminal.status = SubagentStatus::Partial;
            }
            clipped = true;
        }
    }
    terminal
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn terminal_headroom_bounds_escaped_text_and_references_without_dropping_reservations() {
        let digest = |index: u64| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            SubagentDigest::from_bytes(bytes)
        };
        let summary = "\"\\".repeat(8192);
        let terminal = BranchTerminal {
            status: SubagentStatus::Completed,
            summary_sha256: SubagentDigest::from_bytes(crate::sha256(summary.as_bytes())),
            guarded_summary: summary,
            sources: (0..1024)
                .map(|index| SubagentSourceRef {
                    hash: digest(index),
                    index: u64::MAX,
                })
                .collect(),
            coverage: vec![],
            usage: SubagentResources::default(),
            reservation_ids: (0..2000).map(digest).collect(),
            pending_approvals: vec![],
        };
        let bounded = bounded_terminal(terminal.clone());
        assert_eq!(bounded.status, SubagentStatus::Partial);
        assert!(bounded.sources.len() < terminal.sources.len());
        assert_eq!(bounded.reservation_ids, terminal.reservation_ids);
        assert_eq!(bounded.summary_sha256, terminal.summary_sha256);
        assert_eq!(bounded.usage, terminal.usage);
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= 254 * 1024);
        crate::subagents::SubagentBranchBody {
            case_id: "00000000-0000-0000-0000-000000000001".into(),
            turn_id: "00000000-0000-0000-0000-000000000002".into(),
            task_id: digest(1),
            nonce: "00000000-0000-0000-0000-000000000003".into(),
            seq: 1,
            at: 10,
            payload: crate::subagents::SubagentBranchPayload::Terminal(bounded),
            prev: SubagentDigest::from_bytes([0; 32]),
            public_key: digest(2),
        }
        .validate()
        .unwrap();
    }
}
