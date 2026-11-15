use crate::ports::model::output::{CONTINUE_INSTRUCTION, PROVIDER_NOTICE, SECURITY_NOTICE};
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
        request: CompletionRequest,
        cancel: &CancellationToken,
        on_progress: &(dyn Fn(crate::ModelProgress) + Send + Sync),
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        let on_text = |text: &str| on_progress(crate::ModelProgress::TextDelta(text.to_owned()));
        model.output_profile().parameter_value()?;
        let (mut first, usage) = self
            .model_request_once(id, model, request.clone(), cancel, &on_text)
            .await?;
        if !first.truncated || first.text.len() > 1_000_000 || first.text.ends_with(SECURITY_NOTICE)
        {
            return Ok((first, usage));
        }
        let nonce = request
            .messages
            .get(1)
            .and_then(|m| m.content.strip_prefix("<UNTRUSTED_"))
            .and_then(|s| s.split_once('>'))
            .and_then(|(nonce, _)| uuid::Uuid::parse_str(nonce).ok())
            .map(|nonce| nonce.to_string());
        let (used, limit) = match self.continuation_budget(id, usage, nonce).await? {
            ContinuationAdmission::Start { used, limit } => (used, limit),
            ContinuationAdmission::Stop(hint) => {
                first.text.push_str("\n\n");
                first.text.push_str(hint);
                return Ok((first, usage));
            }
        };
        on_progress(crate::ModelProgress::Notice(format!(
            "{PROVIDER_NOTICE} Continuing once…"
        )));
        self.record_model_reply(id, &first.raw).await?;
        self.record_model_usage(id, usage, used, limit).await?;
        let request = continuing_request(request, self.guard.as_ref(), &first.text)?;
        self.audit_local(
            id,
            crate::AuditOrigin::System,
            crate::AuditEventKind::ModelRequest,
            "automatic provider-output continuation; no tools",
            None,
        )
        .await?;
        let (second, second_usage) = match self
            .model_request_once(id, model, request, cancel, &on_text)
            .await
        {
            Ok(reply) => reply,
            Err(error) => {
                self.finish_answer(id, &format!("{}\n\n[The model reached its maximum output. Automatic continuation did not complete; the received answer is retained.]", first.text)).await?;
                return Err(error);
            }
        };
        if !second.calls.is_empty() {
            self.record_model_reply(id, &second.raw).await?;
            let used = self.used_model_tokens(id).await?;
            self.record_model_usage(id, second_usage, used, limit)
                .await?;
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

    async fn continuation_budget(
        &self,
        id: &CaseId,
        usage: Option<ModelUsage>,
        nonce: Option<String>,
    ) -> Result<ContinuationAdmission, AppError> {
        let used = self.used_model_tokens(id).await?;
        let owned = id.clone();
        let (limit, rounds) = self
            .blocking_local(move |local| {
                let limit = local
                    .case_budget_unlocked(&owned)?
                    .require_effective()?
                    .model_tokens;
                let entries = local.audit_log.entries(&owned)?;
                let root_rounds = entries
                    .iter()
                    .rev()
                    .take_while(|e| e.kind != crate::AuditEventKind::Prompt)
                    .filter(|e| e.kind == crate::AuditEventKind::ModelRequest)
                    .count();
                let rounds = if local.subagents.is_some() {
                    nonce
                        .as_deref()
                        .map(|nonce| local.turn_model_rounds_unlocked(&owned, nonce))
                        .transpose()?
                        .map_or(root_rounds, |used| {
                            usize::try_from(used).unwrap_or(usize::MAX)
                        })
                } else {
                    root_rounds
                };
                Ok((limit, rounds))
            })
            .await?;
        let Some(report) = usage else {
            return Ok(ContinuationAdmission::Stop(
                "Automatic continuation was not started because provider usage is unavailable.",
            ));
        };
        let total = used
            .checked_add(report.input_tokens)
            .and_then(|n| n.checked_add(report.output_tokens))
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyModelTokenCountOverflow,
            ))?;
        if total >= limit {
            return Ok(ContinuationAdmission::Stop(
                "The case token budget is exhausted. Review /budget before another request.",
            ));
        }
        if rounds >= self.policy.max_model_rounds_per_turn {
            return Ok(ContinuationAdmission::Stop(
                "The model round limit was reached. Use /continue to resume.",
            ));
        }
        Ok(ContinuationAdmission::Start { used, limit })
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

enum ContinuationAdmission {
    Start { used: u64, limit: u64 },
    Stop(&'static str),
}
fn continuing_request(
    mut request: CompletionRequest,
    guard: &dyn crate::ContentGuard,
    text: &str,
) -> Result<CompletionRequest, AppError> {
    let guarded = crate::ports::model::output::screen_output(guard, text)?;
    request.messages.push(crate::CompletionMessage::text(
        crate::MessageRole::Assistant,
        guarded,
    ));
    request.messages.push(crate::CompletionMessage::text(
        crate::MessageRole::System,
        CONTINUE_INSTRUCTION.into(),
    ));
    request.tools.clear();
    Ok(request)
}
