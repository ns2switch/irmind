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
