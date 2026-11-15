use super::{StartedSubagentPlan, TaskSession, invalid};
use crate::subagents::{BranchModelReply, SubagentBranchPayload, SubagentStatus, SubagentTaskSpec};
use crate::{AppError, Engine};

impl Engine<'_> {
    pub(super) fn retain_child_reply(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        reply: &mut BranchModelReply,
        status: &mut SubagentStatus,
    ) -> Result<(), AppError> {
        let mut template_reply = reply.clone();
        template_reply.guarded_text.clear();
        let template = self.child_entry(
            started,
            task,
            state.seq + 1,
            state.previous,
            SubagentBranchPayload::ModelReply(template_reply),
        )?;
        let frame_size = |text: &str, status| {
            let mut entry = template.clone();
            if let SubagentBranchPayload::ModelReply(reply) = &mut entry.body.payload {
                text.clone_into(&mut reply.guarded_text);
            }
            let terminal = self.child_entry(
                started,
                task,
                state.seq + 2,
                entry.hash,
                SubagentBranchPayload::Terminal(state.terminal(status)),
            )?;
            // Only sizing an uncommitted candidate. The final entry is validated,
            // hashed and signed by child_model_reply after fitting.
            serde_json::to_vec(&[entry, terminal])
                .map(|bytes| bytes.len())
                .map_err(|_| invalid())
        };
        if frame_size(&reply.guarded_text, *status)? <= crate::ports::model::output::FRAME_BYTES {
            return Ok(());
        }
        *status = SubagentStatus::Partial;
        let fitted = crate::ports::model::output::fit_frame(&reply.guarded_text, |text| {
            frame_size(text, *status)
        })?;
        reply.guarded_text = fitted;
        reply.truncated = true;
        reply.tool_calls.clear();
        state.partial = true;
        Ok(())
    }
}

impl Engine<'_> {
    pub(super) fn prepare_child_continuation(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        entries: &mut Vec<crate::subagents::SubagentBranchEntry>,
    ) -> Result<(), AppError> {
        self.compact_child_continuation(started, task, state, entries)?;
        state.messages.push(crate::CompletionMessage::text(
            crate::MessageRole::System,
            crate::ports::model::output::CONTINUE_INSTRUCTION.into(),
        ));
        Ok(())
    }
    fn compact_child_continuation(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        state: &mut TaskSession,
        entries: &mut Vec<crate::subagents::SubagentBranchEntry>,
    ) -> Result<(), AppError> {
        if super::messages::canonical(&state.messages)?.len() <= 40_000 {
            return Ok(());
        }
        let Some(message) = state
            .messages
            .iter_mut()
            .rev()
            .find(|m| m.role == crate::MessageRole::Assistant && m.tool_calls.is_empty())
        else {
            return Ok(());
        };
        let start = message
            .content
            .ceil_char_boundary(message.content.len().saturating_sub(8_000));
        let text = format!(
            "Previous answer is retained in the signed branch. Continue from this final excerpt:\n<UNTRUSTED_{}>\n{}\n</UNTRUSTED_{}>",
            task.nonce,
            crate::isolate_untrusted(
                &message.content[start..],
                &uuid::Uuid::parse_str(&task.nonce).map_err(|_| invalid())?
            ),
            task.nonce
        );
        message.content.clone_from(&text);
        let previous = entries.last().ok_or_else(invalid)?;
        let compacted = self.child_entry(
            started,
            task,
            previous.body.seq + 1,
            previous.hash,
            SubagentBranchPayload::Compaction(crate::subagents::BranchCompaction {
                text_sha256: crate::subagents::SubagentDigest::from_bytes(crate::sha256(
                    text.as_bytes(),
                )),
                guarded_text: text,
                replaced_first: previous.body.seq,
                replaced_last: previous.body.seq,
            }),
        )?;
        entries.push(compacted);
        Ok(())
    }
}
