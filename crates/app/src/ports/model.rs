use crate::*;
pub struct ModelResponse {
    pub text: String,
    pub calls: Vec<ProposedCall>,
    pub raw: String,
}

impl std::fmt::Debug for ModelResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelResponse")
            .field("text_bytes", &self.text.len())
            .field("call_count", &self.calls.len())
            .field("raw_bytes", &self.raw.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ModelPricing {
    pub input_microusd_per_million: u64,
    pub output_microusd_per_million: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageEvent {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost_microusd: Option<u64>,
}

pub fn summarize_usage(entries: &[SignedEntry]) -> Result<UsageEvent, AppError> {
    let mut total = UsageEvent {
        input_tokens: 0,
        output_tokens: 0,
        estimated_cost_microusd: None,
    };
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == irmind_domain::AuditEventKind::ModelUsage)
    {
        let usage: UsageEvent =
            serde_json::from_str(&entry.payload).map_err(|_| AppError::InvalidChain(entry.seq))?;
        total.input_tokens = total
            .input_tokens
            .checked_add(usage.input_tokens)
            .ok_or(AppError::InvalidChain(entry.seq))?;
        total.output_tokens = total
            .output_tokens
            .checked_add(usage.output_tokens)
            .ok_or(AppError::InvalidChain(entry.seq))?;
        if let Some(cost) = usage.estimated_cost_microusd {
            total.estimated_cost_microusd = Some(
                total
                    .estimated_cost_microusd
                    .unwrap_or(0)
                    .checked_add(cost)
                    .ok_or(AppError::InvalidChain(entry.seq))?,
            );
        }
    }
    Ok(total)
}

pub type ModelStream = std::pin::Pin<Box<dyn Stream<Item = Result<ModelEvent, AppError>> + Send>>;

#[derive(Debug)]
pub enum ModelEvent {
    Progress(usize),
    Completed {
        response: ModelResponse,
        usage: Option<ModelUsage>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone)]
pub struct CompletionMessage {
    pub role: MessageRole,
    pub content: String,
}

impl std::fmt::Debug for CompletionMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CompletionRequest {
    pub messages: Vec<CompletionMessage>,
    pub tools: Vec<tool_catalog::ToolSpec>,
    pub max_output_tokens: u32,
    pub remaining_case_tokens: u64,
}

impl std::fmt::Debug for CompletionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionRequest")
            .field("message_count", &self.messages.len())
            .field("tool_count", &self.tools.len())
            .field("max_output_tokens", &self.max_output_tokens)
            .field("remaining_case_tokens", &self.remaining_case_tokens)
            .finish()
    }
}

impl CompletionRequest {
    pub fn context(&self) -> Option<&str> {
        self.messages
            .iter()
            .rev()
            .find(|message| message.role == MessageRole::User)
            .map(|message| message.content.as_str())
    }
}

#[async_trait]
pub trait LlmPort: Send + Sync {
    fn descriptor(&self) -> String {
        "unspecified".into()
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError>;
}

pub async fn collect_model_stream(
    mut events: ModelStream,
    cancel: &CancellationToken,
) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
    let mut completed = None;
    loop {
        let event = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            event = events.next() => event,
        };
        let Some(event) = event else { break };
        match event? {
            ModelEvent::Progress(_) if completed.is_none() => {}
            ModelEvent::Completed { response, usage } if completed.is_none() => {
                completed = Some((response, usage));
            }
            _ => {
                return Err(AppError::Fixed(
                    crate::FixedAppError::ModelProviderEmittedDataAfterCompletion,
                ));
            }
        }
    }
    completed.ok_or(AppError::Fixed(
        crate::FixedAppError::ModelProviderStreamEndedWithoutCompletion,
    ))
}

pub fn single_completion_stream(response: ModelResponse, usage: Option<ModelUsage>) -> ModelStream {
    Box::pin(futures_util::stream::once(async move {
        Ok(ModelEvent::Completed { response, usage })
    }))
}
