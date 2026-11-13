use super::{BTreeMap, CancellationToken, ProposedCall, Tool};
pub(super) struct BudgetModel {
    pub(super) requests: std::sync::Mutex<Vec<irmind_app::CompletionRequest>>,
    pub(super) output: Option<&'static str>,
    pub(super) usage: Option<irmind_app::ModelUsage>,
}
#[irmind_app::async_trait]
impl irmind_app::LlmPort for BudgetModel {
    async fn complete(
        &self,
        request: irmind_app::CompletionRequest,
        _: &CancellationToken,
    ) -> Result<irmind_app::ModelStream, irmind_app::AppError> {
        request.validate()?;
        let final_only = request.tools.is_empty() || self.output.is_some();
        self.requests.lock().unwrap().push(request);
        let calls = if final_only {
            vec![]
        } else {
            vec![irmind_app::ModelToolCall::from_proposal(
                "budget_summary",
                ProposedCall {
                    tool: Tool::GraphSummary,
                    args: BTreeMap::new(),
                },
            )?]
        };
        Ok(Box::pin(futures_util::stream::iter([Ok(
            irmind_app::ModelEvent::Completed {
                response: irmind_app::ModelResponse {
                    truncated: false,
                    text: if final_only {
                        self.output
                            .unwrap_or("Completed local evidence review.")
                            .into()
                    } else {
                        String::new()
                    },
                    raw: "synthetic budget boundary response".into(),
                    calls,
                },
                // Deliberately fixed synthetic counters exercise quota boundaries, not billing.
                usage: self.usage,
            },
        )])))
    }
}
