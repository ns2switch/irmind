use crate::{
    AppError, CancellationToken, CaseId, CompletionRequest, Engine, LlmPort, ModelResponse,
    ModelUsage, collect_model_stream_with_progress,
};

impl Engine<'_> {
    pub(super) async fn complete_model_request(
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
