use crate::{
    AppError, CancellationToken, ContentGuard, Deserialize, ProposedCall, Screened, Serialize,
    SignedEntry, Stream, StreamExt, async_trait, tool_catalog,
};
mod cache;
pub(crate) mod output;
mod profile;
pub use cache::{CacheUsage, CacheWriteLifetime};
pub use profile::*;
pub struct ModelResponse {
    pub text: String,
    pub calls: Vec<ModelToolCall>,
    pub raw: String,
    pub truncated: bool,
}

#[derive(Clone)]
pub struct ModelToolCall {
    id: String,
    proposal: ProposedCall,
    arguments_json: String,
}

impl ModelToolCall {
    pub fn new(
        id: String,
        proposal: ProposedCall,
        arguments_json: String,
    ) -> Result<Self, AppError> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
        {
            return Err(AppError::Fixed(crate::FixedAppError::AdapterModel(
                crate::AdapterModelError::MissingProviderToolID,
            )));
        }
        let parsed: serde_json::Value = serde_json::from_str(&arguments_json).map_err(|_| {
            AppError::Fixed(crate::FixedAppError::AdapterPolicy(
                crate::AdapterPolicyError::ToolArgumentsMustBeAnObject,
            ))
        })?;
        let object =
            parsed
                .as_object()
                .ok_or(AppError::Fixed(crate::FixedAppError::AdapterPolicy(
                    crate::AdapterPolicyError::ToolArgumentsMustBeAnObject,
                )))?;
        let same = object.len() == proposal.args.len()
            && object.iter().all(|(key, value)| {
                let encoded = match value {
                    serde_json::Value::String(text) => text.clone(),
                    serde_json::Value::Number(number) => number.to_string(),
                    _ => return false,
                };
                proposal.args.get(key) == Some(&encoded)
            });
        if !same {
            return Err(AppError::Fixed(crate::FixedAppError::AdapterPolicy(
                crate::AdapterPolicyError::ToolArgumentMustBeStringOrNumber,
            )));
        }
        Ok(Self {
            id,
            proposal,
            arguments_json,
        })
    }

    pub fn from_proposal(id: &str, proposal: ProposedCall) -> Result<Self, AppError> {
        let arguments_json = serde_json::to_string(&proposal.args).map_err(|_| {
            AppError::Fixed(crate::FixedAppError::AdapterPolicy(
                crate::AdapterPolicyError::ToolArgumentsMustBeAnObject,
            ))
        })?;
        Self::new(id.to_owned(), proposal, arguments_json)
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn proposal(&self) -> &ProposedCall {
        &self.proposal
    }
    pub fn arguments_json(&self) -> &str {
        &self.arguments_json
    }
    pub fn into_proposal(self) -> ProposedCall {
        self.proposal
    }
}

impl std::fmt::Debug for ModelToolCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelToolCall")
            .field("id", &self.id)
            .field("tool", &self.proposal.tool)
            .field("argument_count", &self.proposal.args.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ModelResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelResponse")
            .field("text_bytes", &self.text.len())
            .field("call_count", &self.calls.len())
            .field("raw_bytes", &self.raw.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "cache::ModelUsageWire")]
pub struct ModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheUsage>,
}

#[derive(Clone, Copy, Debug)]
pub struct ModelPricing {
    pub input_microusd_per_million: u64,
    pub output_microusd_per_million: u64,
    pub cache_read_microusd_per_million: Option<u64>,
    pub cache_write_microusd_per_million: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(try_from = "cache::UsageEventWire")]
pub struct UsageEvent {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheUsage>,
}

pub fn summarize_usage(entries: &[SignedEntry]) -> Result<UsageEvent, AppError> {
    let usage = crate::case_budget_usage(entries)?;
    Ok(UsageEvent {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        estimated_cost_microusd: usage.cost_microusd,
        cache: if usage.cache_reporting_complete {
            usage.reported_cache
        } else {
            None
        },
    })
}

pub type ModelStream = std::pin::Pin<Box<dyn Stream<Item = Result<ModelEvent, AppError>> + Send>>;

pub enum ModelEvent {
    Progress(usize),
    TextDelta(String),
    Completed {
        response: ModelResponse,
        usage: Option<ModelUsage>,
    },
}

pub enum ModelProgress {
    Notice(String),
    RoundStarted { round: usize, limit: usize },
    TextDelta(String),
    ToolProposed(String),
}

impl std::fmt::Debug for ModelEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Progress(bytes) => f.debug_tuple("Progress").field(bytes).finish(),
            Self::TextDelta(text) => f.debug_tuple("TextDelta").field(&text.len()).finish(),
            Self::Completed { response, usage } => f
                .debug_struct("Completed")
                .field("response", response)
                .field("usage", usage)
                .finish(),
        }
    }
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
    pub tool_calls: Vec<ModelToolCall>,
    pub tool_call_id: Option<String>,
}

impl CompletionMessage {
    pub fn text(role: MessageRole, content: String) -> Self {
        Self {
            role,
            content,
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }

    pub fn assistant_tools(content: String, tool_calls: Vec<ModelToolCall>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content,
            tool_calls,
            tool_call_id: None,
        }
    }

    pub fn tool_result(tool_call_id: String, content: String) -> Self {
        Self {
            role: MessageRole::Tool,
            content,
            tool_calls: Vec::new(),
            tool_call_id: Some(tool_call_id),
        }
    }
}

impl std::fmt::Debug for CompletionMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .field("tool_call_count", &self.tool_calls.len())
            .field("has_tool_call_id", &self.tool_call_id.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub struct CompletionRequest {
    pub messages: Vec<CompletionMessage>,
    pub tools: Vec<tool_catalog::ToolSpec>,
}

impl std::fmt::Debug for CompletionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionRequest")
            .field("message_count", &self.messages.len())
            .field("tool_count", &self.tools.len())
            .finish()
    }
}

impl CompletionRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        let mut pending = std::collections::HashSet::new();
        for message in &self.messages {
            match message.role {
                MessageRole::Assistant => {
                    if message.tool_call_id.is_some() {
                        return Err(AppError::Model(
                            "assistant message has a tool result ID".into(),
                        ));
                    }
                    for call in &message.tool_calls {
                        if !pending.insert(call.id()) {
                            return Err(AppError::Model("duplicate tool call ID".into()));
                        }
                    }
                }
                MessageRole::Tool => {
                    let Some(id) = message.tool_call_id.as_deref() else {
                        return Err(AppError::Model("tool result has no call ID".into()));
                    };
                    if !pending.remove(id) || !message.tool_calls.is_empty() {
                        return Err(AppError::Model("tool result has no matching call".into()));
                    }
                }
                _ if message.tool_call_id.is_some() || !message.tool_calls.is_empty() => {
                    return Err(AppError::Model("invalid message tool fields".into()));
                }
                _ => {}
            }
        }
        if !pending.is_empty() {
            return Err(AppError::Model("tool calls are missing results".into()));
        }
        Ok(())
    }

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

    fn output_profile(&self) -> ModelOutputProfile {
        ModelOutputProfile::default()
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError>;
}

pub async fn collect_model_stream(
    events: ModelStream,
    cancel: &CancellationToken,
) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
    collect_model_stream_with_progress(events, cancel, |_| {}).await
}

pub async fn collect_model_stream_with_progress(
    mut events: ModelStream,
    cancel: &CancellationToken,
    mut on_text: impl FnMut(&str),
) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
    let mut completed = None;
    let mut preview = String::new();
    loop {
        let event = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            event = events.next() => event,
        };
        let Some(event) = event else { break };
        let event = match event {
            Ok(event) => event,
            Err(AppError::Fixed(crate::FixedAppError::AdapterModel(
                crate::AdapterModelError::ProviderStreamExceeds2MB,
            ))) if completed.is_none() => {
                return Ok((
                    ModelResponse {
                        text: format!("{preview}\n\n{}", output::SECURITY_NOTICE),
                        calls: Vec::new(),
                        raw: "Provider stream reached IRMind security limit; usage unavailable"
                            .into(),
                        truncated: false,
                    },
                    None,
                ));
            }
            Err(error) => return Err(error),
        };
        match event {
            ModelEvent::Progress(_) if completed.is_none() => {}
            ModelEvent::TextDelta(text) if completed.is_none() => {
                if preview.len().saturating_add(text.len()) > 2_000_000 {
                    return Err(AppError::Fixed(
                        crate::FixedAppError::ModelStreamPreviewExceedsLimit,
                    ));
                }
                preview.push_str(&text);
                on_text(&text);
            }
            ModelEvent::Completed { response, usage } if completed.is_none() => {
                if !preview.is_empty() && preview != response.text {
                    return Err(AppError::Fixed(
                        crate::FixedAppError::ModelStreamTextMismatch,
                    ));
                }
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

/// Screen a bounded, possibly unfinished preview without exposing open PEM data.
pub fn screen_model_preview(guard: &dyn ContentGuard, text: &str) -> Result<Screened, AppError> {
    guard.screen(output::complete_prefix(text))
}

pub fn single_completion_stream(response: ModelResponse, usage: Option<ModelUsage>) -> ModelStream {
    Box::pin(futures_util::stream::once(async move {
        Ok(ModelEvent::Completed { response, usage })
    }))
}
