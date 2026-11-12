use irmind_app::{
    AppError, CancellationToken, CompletionRequest, LlmPort, ModelEvent, ModelResponse,
    ModelStream, ModelToolCall,
};
use irmind_domain::{ProposedCall, Tool};
use std::{collections::BTreeMap, sync::Mutex};
pub(super) struct Sequence {
    pub(super) requests: Mutex<Vec<CompletionRequest>>,
    calls: Vec<ProposedCall>,
}
impl Sequence {
    pub(super) fn new(calls: Vec<ProposedCall>) -> Self {
        Self {
            requests: Mutex::default(),
            calls,
        }
    }
}
pub(super) fn call(tool: Tool, args: &[(&str, &str)]) -> ProposedCall {
    ProposedCall {
        tool,
        args: args
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect::<BTreeMap<_, _>>(),
    }
}
#[irmind_app::async_trait]
impl LlmPort for Sequence {
    async fn complete(
        &self,
        request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let mut requests = self.requests.lock().unwrap();
        let index = requests.len();
        requests.push(request);
        let calls = self
            .calls
            .get(index)
            .map(|p| ModelToolCall::from_proposal(&format!("sequence_{index}"), p.clone()).unwrap())
            .into_iter()
            .collect();
        Ok(Box::pin(futures_util::stream::iter([Ok(
            ModelEvent::Completed {
                response: ModelResponse {
                    truncated: false,
                    text: if index >= self.calls.len() {
                        "Synthetic review complete.".into()
                    } else {
                        String::new()
                    },
                    raw: "scripted".into(),
                    calls,
                },
                usage: None,
            },
        )])))
    }
}
