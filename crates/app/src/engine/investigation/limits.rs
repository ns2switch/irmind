use super::TurnContext;
use crate::{
    AppError, AuditEventKind, CancellationToken, CaseId, CompletionMessage, CompletionRequest,
    Engine, LlmPort, MessageRole, ModelProgress,
};

#[derive(Clone, Copy)]
pub(super) enum TurnLimit {
    ModelRounds,
    ModelTokens,
    ToolCalls,
    CloudTransfer,
}

impl TurnLimit {
    fn reason(self) -> &'static str {
        match self {
            Self::ModelRounds => "model round limit",
            Self::ModelTokens => "model token limit",
            Self::ToolCalls => "case tool call limit",
            Self::CloudTransfer => "case cloud transfer limit",
        }
    }

    fn continuation_hint(self) -> &'static str {
        match self {
            Self::ModelRounds => "Use /continue to resume.",
            _ => {
                "Use /budget to review or increase the signed case allocation before /continue; the organization ceiling still applies."
            }
        }
    }
}

impl Engine<'_> {
    pub(super) async fn finish_token_exhaustion(
        &self,
        id: &CaseId,
        answer: &str,
    ) -> Result<String, AppError> {
        let summary = self.completed_work_summary(id).await?;
        let owned = id.clone();
        let notice = self
            .blocking_local(move |local| {
                Ok(local
                    .case_budget_unlocked(&owned)?
                    .notice("model token limit"))
            })
            .await?;
        self.finish_answer(
            id,
            &format!(
                "{answer}\n{summary}\n\n{notice} Use /continue after reviewing the allocation."
            ),
        )
        .await
    }

    pub(super) async fn completed_work_summary(&self, id: &CaseId) -> Result<String, AppError> {
        let id = id.clone();
        self.blocking_local(move |local| {
            let entries = local.audit_log.entries(&id)?;
            let recent = entries.iter().rev().take_while(|e| e.kind != AuditEventKind::Prompt);
            let completed = recent.filter(|e| e.kind == AuditEventKind::ToolResult).count();
            let findings = local.findings_unlocked(&id, &entries)?.len();
            Ok(format!("Recorded work: {completed} completed tool results in this turn; {findings} case findings remain available. Review pending approvals and findings before continuing."))
        }).await
    }

    pub(super) async fn finish_limited_turn(
        &self,
        id: &CaseId,
        model: &dyn LlmPort,
        turn: &mut TurnContext,
        limit: TurnLimit,
        cancel: &CancellationToken,
        on_text: &(dyn Fn(ModelProgress) + Send + Sync),
    ) -> Result<String, AppError> {
        let reason = limit.reason();
        self.audit_local(
            id,
            crate::AuditOrigin::Policy,
            AuditEventKind::BudgetExceeded,
            reason,
            None,
        )
        .await?;
        let used = self.used_model_tokens(id).await?;
        let remaining = turn.budget.model_tokens.saturating_sub(used);
        let hint = limit.continuation_hint();
        let owned = id.clone();
        let notice = self
            .blocking_local(move |local| Ok(local.case_budget_unlocked(&owned)?.notice(reason)))
            .await?;
        let rounds = self
            .shared_round_number(id, turn, (1, self.policy.max_model_rounds_per_turn))
            .await?;
        if remaining == 0 || rounds.0 > rounds.1 {
            let summary = self.completed_work_summary(id).await?;
            return self
                .finish_answer(id, &format!("{summary}\n\n{notice} {hint}"))
                .await;
        }
        let mut messages = turn.messages.clone();
        messages.push(CompletionMessage::text(MessageRole::System,
            format!("The {reason} was reached. Summarize verified findings and pending work. Do not use tools. End with: {hint}")));
        let request = CompletionRequest {
            messages,
            tools: Vec::new(),
        };
        on_text(ModelProgress::RoundStarted {
            round: self.policy.max_model_rounds_per_turn,
            limit: self.policy.max_model_rounds_per_turn,
        });
        let (answer, usage) = self
            .complete_model_request(id, model, request, cancel, on_text)
            .await?;
        if !answer.calls.is_empty() {
            return Err(AppError::Model(
                "provider returned tools when none were offered".into(),
            ));
        }
        self.record_model_reply(id, &answer.raw).await?;
        let used = self.used_model_tokens(id).await?;
        self.record_model_usage(id, usage, used, turn.budget.model_tokens)
            .await?;
        let mut summary = if answer.text.trim().is_empty() {
            format!(
                "No model summary text was returned. {}",
                self.completed_work_summary(id).await?
            )
        } else {
            answer.text
        };
        if answer.truncated {
            summary.push_str("\n[Model summary cut off by output limit]");
        }
        self.finish_answer(id, &format!("{summary}\n\n{notice} {hint}"))
            .await
    }
}
