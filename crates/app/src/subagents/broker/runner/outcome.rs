use super::{ModelStep, bounded_text, invalid};
use crate::subagents::{
    BranchModelReply, BranchTerminal, BranchToolCall, SubagentDigest, SubagentStatus,
    SubagentTaskSpec,
};
use crate::{AppError, Engine, ModelResponse, ModelUsage, UsageEvent};

pub(super) struct ModelOutcome {
    pub terminal: BranchTerminal,
    pub reply: Option<BranchModelReply>,
    pub report: Option<UsageEvent>,
}

impl Engine<'_> {
    pub(super) fn child_model_outcome(
        &self,
        task: &SubagentTaskSpec,
        step: &ModelStep,
        response: Result<(ModelResponse, Option<ModelUsage>), AppError>,
    ) -> Result<ModelOutcome, AppError> {
        let mut outcome = ModelOutcome {
            terminal: BranchTerminal {
                status: if matches!(&response, Err(AppError::Cancelled)) {
                    SubagentStatus::Cancelled
                } else {
                    SubagentStatus::Error
                },
                guarded_summary:
                    "The model request did not complete; unreported usage remains reserved.".into(),
                summary_sha256: SubagentDigest::from_bytes([0; 32]),
                sources: vec![],
                coverage: vec!["No evidence queries were executed.".into()],
                usage: step.reservation.amount,
                reservation_ids: vec![step.reservation.operation_id],
                pending_approvals: vec![],
            },
            reply: None,
            report: None,
        };
        if matches!(&response, Err(AppError::Cancelled)) && self.clock.now()? >= task.deadline_at {
            outcome.terminal.guarded_summary =
                "The subagent reached its deadline; unreported usage remains reserved.".into();
        }
        if let Ok((answer, report)) = response {
            if let Some(report) = report {
                let tokens = report
                    .input_tokens
                    .checked_add(report.output_tokens)
                    .ok_or_else(invalid)?;
                outcome.terminal.usage.tokens = tokens;
                outcome.report = Some(UsageEvent {
                    cache: report.cache,
                    input_tokens: report.input_tokens,
                    output_tokens: report.output_tokens,
                    estimated_cost_microusd: self.usage_cost(report)?,
                });
            }
            if self.clock.now()? > task.deadline_at {
                outcome.terminal.status = SubagentStatus::Cancelled;
                outcome.terminal.guarded_summary = "The subagent reached its deadline; reported usage is retained and unreported usage remains reserved.".into();
                return Ok(outcome.committed());
            }
            let text =
                crate::ports::model::output::screen_output(self.guard.as_ref(), &answer.text)?;
            let truncated =
                answer.truncated || text.ends_with(crate::ports::model::output::SECURITY_NOTICE);
            outcome.terminal.guarded_summary = bounded_text(text.clone());
            outcome.terminal.status = if answer.calls.is_empty() && !truncated {
                SubagentStatus::Completed
            } else {
                SubagentStatus::Partial
            };
            outcome.reply = Some(BranchModelReply {
                call_id: format!("model_{}", step.reservation.request_ordinal),
                guarded_text: text,
                truncated,
                tool_calls: answer
                    .calls
                    .iter()
                    .map(|call| BranchToolCall {
                        id: call.id().into(),
                        tool: call.proposal().tool.as_str().into(),
                        arguments: call.proposal().args.clone(),
                    })
                    .collect(),
                usage: report,
            });
        }
        Ok(outcome.committed())
    }
}
impl ModelOutcome {
    fn committed(mut self) -> Self {
        self.terminal.summary_sha256 =
            SubagentDigest::from_bytes(crate::sha256(self.terminal.guarded_summary.as_bytes()));
        self
    }
}
