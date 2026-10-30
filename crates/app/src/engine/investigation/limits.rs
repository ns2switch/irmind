use super::TurnContext;
use crate::{
    AppError, AuditEventKind, CancellationToken, CaseId, CompletionMessage, CompletionRequest,
    Engine, LlmPort, MessageRole, ModelProgress,
};

fn continuation_hint(reason: &str) -> &'static str {
    if reason == "model round limit" {
        "Use /continue to resume."
    } else {
        "Increase the case policy limit before using /continue."
    }
}

impl Engine<'_> {
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
        let remaining = self.policy.max_model_tokens_per_case.saturating_sub(used);
        let hint = continuation_hint(reason);
        if remaining == 0 {
            return self.finish_answer(id, &format!(
                "Limit reached ({reason}). The completed tool results remain in this case. {hint}"
            )).await;
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
        self.record_model_usage(id, usage, used).await?;
        let mut summary = if answer.text.trim().is_empty() {
            "No model summary was returned; review the signed tool results.".to_owned()
        } else {
            answer.text
        };
        if answer.truncated {
            summary.push_str("\n[Model summary cut off by output limit]");
        }
        self.finish_answer(
            id,
            &format!("{summary}\n\nLimit reached ({reason}). {hint}"),
        )
        .await
    }
}
