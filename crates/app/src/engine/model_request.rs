use crate::{
    AppError, CancellationToken, CaseId, CompletionRequest, Engine, LlmPort, ModelResponse,
    ModelUsage, collect_model_stream_with_progress,
};

impl Engine<'_> {
    pub(super) async fn record_model_reply(&self, id: &CaseId, text: &str) -> Result<(), AppError> {
        let screened = crate::ports::model::output::screen_output(self.guard.as_ref(), text)?;
        let owned = id.clone();
        self.blocking_local(move |local| {
            local
                .audit_model_text(&owned, crate::AuditEventKind::ModelReply, &screened)
                .map(|_| ())
        })
        .await
    }

    pub(super) async fn complete_model_request(
        &self,
        id: &CaseId,
        model: &dyn LlmPort,
        mut request: CompletionRequest,
        cancel: &CancellationToken,
        on_text: &(dyn Fn(&str) + Send + Sync),
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        use crate::ports::model::output::{CONTINUE_INSTRUCTION, PROVIDER_NOTICE, SECURITY_NOTICE};
        model.output_profile().parameter_value()?;
        let (mut first, usage) = self
            .model_request_once(id, model, request.clone(), cancel, on_text)
            .await?;
        if !first.truncated || first.text.len() > 1_000_000 || first.text.ends_with(SECURITY_NOTICE)
        {
            return Ok((first, usage));
        }
        let used = self.used_model_tokens(id).await?;
        let owned = id.clone();
        let (limit, rounds) = self
            .blocking_local(move |local| {
                let limit = local
                    .case_budget_unlocked(&owned)?
                    .require_effective()?
                    .model_tokens;
                let entries = local.audit_log.entries(&owned)?;
                let rounds = entries
                    .iter()
                    .rev()
                    .take_while(|e| e.kind != crate::AuditEventKind::Prompt)
                    .filter(|e| e.kind == crate::AuditEventKind::ModelRequest)
                    .count();
                Ok((limit, rounds))
            })
            .await?;
        let Some(report) = usage else {
            return Ok((first, usage));
        };
        let total = used
            .checked_add(report.input_tokens)
            .and_then(|n| n.checked_add(report.output_tokens))
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyModelTokenCountOverflow,
            ))?;
        if total >= limit || rounds >= self.policy.max_model_rounds_per_turn {
            return Ok((first, usage));
        }
        self.record_model_reply(id, &first.raw).await?;
        self.record_model_usage(id, usage, used, limit).await?;
        let guarded = crate::ports::model::output::screen_output(self.guard.as_ref(), &first.text)?;
        request.messages.push(crate::CompletionMessage::text(
            crate::MessageRole::Assistant,
            guarded,
        ));
        request.messages.push(crate::CompletionMessage::text(
            crate::MessageRole::System,
            CONTINUE_INSTRUCTION.into(),
        ));
        request.tools.clear();
        self.audit_local(
            id,
            crate::AuditOrigin::System,
            crate::AuditEventKind::ModelRequest,
            "automatic provider-output continuation; no tools",
            None,
        )
        .await?;
        let (second, second_usage) = self
            .model_request_once(id, model, request, cancel, on_text)
            .await?;
        if !second.calls.is_empty() {
            return Err(AppError::Model(
                "provider returned tools during a tool-free continuation".into(),
            ));
        }
        first.text.push_str(&second.text);
        first.text.push_str("\n\n[");
        first.text.push_str(PROVIDER_NOTICE);
        first.text.push_str(" Continued automatically once.]");
        first.raw = second.raw;
        first.calls.clear();
        first.truncated = second.truncated;
        // The first usage/reply is already committed; callers commit the second.
        Ok((first, second_usage))
    }

    async fn model_request_once(
        &self,
        id: &CaseId,
        model: &dyn LlmPort,
        request: CompletionRequest,
        cancel: &CancellationToken,
        on_text: &(dyn Fn(&str) + Send + Sync),
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        let started = std::time::Instant::now();
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            answer = async {
                let events = model.complete(request, cancel).await?;
                collect_model_stream_with_progress(events, cancel, on_text).await
            } => answer,
        };
        crate::diagnostics::model_finished(result.is_ok(), started.elapsed());
        match result {
            Ok(answer) => Ok(answer),
            Err(AppError::Cancelled) => {
                self.audit_local(
                    id,
                    crate::AuditOrigin::System,
                    irmind_domain::AuditEventKind::Cancelled,
                    "model request cancelled",
                    None,
                )
                .await?;
                Err(AppError::Cancelled)
            }
            Err(error) => {
                self.audit_local(
                    id,
                    crate::AuditOrigin::System,
                    irmind_domain::AuditEventKind::ModelError,
                    &error.to_string(),
                    None,
                )
                .await?;
                Err(error)
            }
        }
    }
}
