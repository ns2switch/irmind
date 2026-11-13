use super::TurnContext;
use crate::{
    AppError, AuditEventKind, CancellationToken, CaseId, CompletionMessage, CompletionRequest,
    Engine, LlmPort, MessageRole, ModelProgress,
};

fn continuation_hint(reason: &str) -> &'static str {
    if reason == "model round limit" {
        "Use /continue to resume."
    } else {
        "Use /budget to review or increase the signed case allocation before /continue; the organization ceiling still applies."
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
        reason: &str,
        cancel: &CancellationToken,
        on_text: &(dyn Fn(ModelProgress) + Send + Sync),
    ) -> Result<String, AppError> {
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
        let hint = continuation_hint(reason);
        let owned = id.clone();
        let reason_owned = reason.to_owned();
        let notice = self
            .blocking_local(move |local| {
                Ok(local.case_budget_unlocked(&owned)?.notice(&reason_owned))
            })
            .await?;
        if remaining == 0 {
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
            max_output_tokens: remaining.min(512) as u32,
            remaining_case_tokens: remaining,
        };
        on_text(ModelProgress::RoundStarted {
            round: self.policy.max_model_rounds_per_turn,
            limit: self.policy.max_model_rounds_per_turn,
        });
        let (answer, usage) = self
            .complete_model_request(id, model, request, cancel, &|text| {
                on_text(ModelProgress::TextDelta(text.to_owned()));
            })
            .await?;
        if !answer.calls.is_empty() {
            return Err(AppError::Model(
                "provider returned tools when none were offered".into(),
            ));
        }
        self.audit_local(
            id,
            crate::AuditOrigin::Model,
            AuditEventKind::ModelReply,
            &answer.raw,
            None,
        )
        .await?;
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
