#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, CompletionMessage, CompletionRequest, LlmPort, MessageRole,
    ModelEvent, ModelStream, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

mod stream;

pub const MODULE_ID: &str = "llm-anthropic";
const API_VERSION: &str = "2026-10-21";

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: MODULE_ID,
    version: "0.1.0",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[
        ConfigField {
            name: "IRMIND_ANTHROPIC_BASE_URL",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_ANTHROPIC_MODEL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "ANTHROPIC_API_KEY",
            required: true,
            secret: true,
        },
    ],
};

pub struct Anthropic {
    async_client: reqwest::Client,
    endpoint: reqwest::Url,
    key: SecretString,
    model: String,
}

fn trusted_system(messages: &[CompletionMessage]) -> Result<String, AppError> {
    let mut trusted = Vec::new();
    for message in messages
        .iter()
        .filter(|message| message.role == MessageRole::System)
    {
        if message.content.contains("UNTRUSTED_") {
            return Err(AppError::Model(
                "untrusted data cannot be an Anthropic system instruction".into(),
            ));
        }
        trusted.push(message.content.as_str());
    }
    Ok(trusted.join("\n"))
}

impl Anthropic {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let model = config.required_value("IRMIND_ANTHROPIC_MODEL")?;
        let key = config
            .required_secret("ANTHROPIC_API_KEY")?
            .expose_secret()
            .to_owned();
        Self::new_with_base(
            config
                .value("IRMIND_ANTHROPIC_BASE_URL")
                .unwrap_or("https://api.anthropic.com/"),
            model,
            key,
        )
    }

    pub fn new(model: &str, key: String) -> Result<Self, AppError> {
        Self::new_with_base("https://api.anthropic.com/", model, key)
    }

    fn new_with_base(base_url: &str, model: &str, key: String) -> Result<Self, AppError> {
        let mut endpoint = reqwest::Url::parse(base_url)
            .map_err(|_| AppError::Model("invalid Anthropic API URL".into()))?;
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || (endpoint.scheme() != "https"
                && !(endpoint.scheme() == "http"
                    && matches!(endpoint.host_str(), Some("127.0.0.1" | "::1" | "localhost"))))
        {
            return Err(AppError::Model(
                "Anthropic API URL requires HTTPS or loopback HTTP".into(),
            ));
        }
        endpoint.set_path("/v1/messages");
        if model.trim().is_empty()
            || model.len() > 200
            || !model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::InvalidAnthropicModelID,
            )));
        }
        if key.trim().is_empty() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::AnthropicAPIKeyIsEmpty,
            )));
        }
        let async_client = irmind_http::client_builder(std::time::Duration::from_secs(90), false)
            .build()
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::AnthropicHTTPClientUnavailable,
                ))
            })?;
        Ok(Self {
            async_client,
            endpoint,
            key: SecretString::from(key),
            model: model.to_owned(),
        })
    }

    fn body(&self, request: &CompletionRequest) -> Result<serde_json::Value, AppError> {
        request.validate()?;
        if request.max_output_tokens == 0 || request.remaining_case_tokens == 0 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ModelTokenBudgetIsEmpty,
            )));
        }
        let tools = request
            .tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.parameters,
                })
            })
            .collect::<Vec<_>>();
        let system = trusted_system(&request.messages)?;
        let mut messages = Vec::<serde_json::Value>::new();
        for message in request
            .messages
            .iter()
            .filter(|m| m.role != MessageRole::System)
        {
            match message.role {
                MessageRole::Assistant if !message.tool_calls.is_empty() => {
                    let mut blocks = Vec::new();
                    if !message.content.is_empty() {
                        blocks.push(json!({"type":"text","text":message.content}));
                    }
                    for call in &message.tool_calls {
                        let input: serde_json::Value = serde_json::from_str(call.arguments_json())
                            .map_err(|_| AppError::Model("invalid tool arguments".into()))?;
                        blocks.push(json!({"type":"tool_use","id":call.id(),
                            "name":call.proposal().tool.as_str(),"input":input}));
                    }
                    messages.push(json!({"role":"assistant","content":blocks}));
                }
                MessageRole::Tool => {
                    let block = json!({"type":"tool_result",
                        "tool_use_id":message.tool_call_id,"content":message.content});
                    if let Some(last) = messages.last_mut()
                        && last["role"] == "user"
                        && last["content"].is_array()
                    {
                        if let Some(blocks) = last["content"].as_array_mut() {
                            blocks.push(block);
                        }
                    } else {
                        messages.push(json!({"role":"user","content":[block]}));
                    }
                }
                MessageRole::User | MessageRole::Assistant => messages.push(json!({
                    "role":if message.role == MessageRole::User {"user"} else {"assistant"},
                    "content":message.content
                })),
                MessageRole::System => {}
            }
        }
        let mut body = json!({
            "model": self.model,
            "max_tokens": u64::from(request.max_output_tokens).min(request.remaining_case_tokens),
            "system": system,
            "messages": messages,
            "stream": true,
        });
        if !tools.is_empty() {
            body["tools"] = json!(tools);
            body["tool_choice"] = json!({"type":"auto","disable_parallel_tool_use":true});
        }
        Ok(body)
    }
}

impl Module for Anthropic {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_llm(MODULE_ID, self)
    }
}

#[async_trait]
impl LlmPort for Anthropic {
    fn descriptor(&self) -> String {
        format!(
            "module={MODULE_ID};model={};endpoint_sha256={}",
            self.model,
            irmind_app::hex(&irmind_app::sha256(self.endpoint.as_str().as_bytes()))
        )
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let body = self.body(&request)?;
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = self.async_client.post(self.endpoint.clone())
                .bearer_auth(self.key.expose_secret())
                .header("anthropic-version", API_VERSION)
                .json(&body)
                .send() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterModel(irmind_app::AdapterModelError::AnthropicRequestFailed)))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Model(format!(
                "provider status {}",
                response.status()
            )));
        }
        let cancel = cancel.clone();
        Ok(Box::pin(async_stream::try_stream! {
            let mut response = response;
            let mut raw = Vec::new();
            let mut preview = stream::TextPreview::default();
            loop {
                let chunk = tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(AppError::Cancelled),
                    result = response.chunk() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterModel(irmind_app::AdapterModelError::AnthropicResponseFailed))),
                }?;
                let Some(chunk) = chunk else { break };
                if raw.len().saturating_add(chunk.len()) > 2_000_000 {
                    Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(irmind_app::AdapterModelError::ProviderStreamExceeds2MB)))?;
                }
                raw.extend_from_slice(&chunk);
                for text in preview.push(&chunk)? {
                    yield ModelEvent::TextDelta(text);
                }
                yield ModelEvent::Progress(chunk.len());
            }
            let (response, usage) = stream::parse(raw.as_slice())?;
            yield ModelEvent::Completed { response, usage: Some(usage) };
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn native_request_maps_common_tools_and_keeps_key_out_of_audit() {
        let adapter = Anthropic::new("claude-sonnet-4-6", "test-secret".into()).unwrap();
        let catalog = irmind_app::tool_catalog::catalog();
        let body = adapter
            .body(&CompletionRequest {
                messages: vec![irmind_app::CompletionMessage {
                    role: MessageRole::User,
                    content: "investigate".into(),
                    tool_calls: Vec::new(),
                    tool_call_id: None,
                }],
                tools: catalog[..1].to_vec(),
                max_output_tokens: 2048,
                remaining_case_tokens: 10_000,
            })
            .unwrap();
        assert_eq!(body["tools"][0]["name"], "evidence_search");
        assert_eq!(body["tools"][0]["input_schema"], catalog[0].parameters);
        assert_eq!(body["tool_choice"]["disable_parallel_tool_use"], true);
        assert!(!adapter.descriptor().contains("test-secret"));
        assert!(Anthropic::new("", "key".into()).is_err());
        assert!(Anthropic::new("claude-sonnet-4-6", String::new()).is_err());
    }

    #[test]
    fn native_request_uses_tool_use_and_tool_result_blocks_with_matching_ids() {
        let adapter = Anthropic::new("synthetic", "test-secret".into()).unwrap();
        let proposal = irmind_app::ProposedCall {
            tool: irmind_app::Tool::EvidenceSearch,
            args: std::collections::BTreeMap::from([("query".into(), "AssumeRole".into())]),
        };
        let call = irmind_app::ModelToolCall::from_proposal("toolu_synthetic", proposal).unwrap();
        let request = CompletionRequest {
            messages: vec![
                irmind_app::CompletionMessage::text(MessageRole::User, "Find the event".into()),
                irmind_app::CompletionMessage::assistant_tools("Searching".into(), vec![call]),
                irmind_app::CompletionMessage::tool_result(
                    "toolu_synthetic".into(),
                    "<UNTRUSTED_test>event</UNTRUSTED_test>".into(),
                ),
            ],
            tools: irmind_app::tool_catalog::catalog()[..1].to_vec(),
            max_output_tokens: 128,
            remaining_case_tokens: 1_000,
        };
        let body = adapter.body(&request).unwrap();
        assert_eq!(body["messages"][1]["content"][1]["type"], "tool_use");
        assert_eq!(body["messages"][1]["content"][1]["id"], "toolu_synthetic");
        assert_eq!(body["messages"][2]["content"][0]["type"], "tool_result");
        assert_eq!(
            body["messages"][2]["content"][0]["tool_use_id"],
            "toolu_synthetic"
        );
        let mut final_request = request;
        final_request.tools.clear();
        let final_body = adapter.body(&final_request).unwrap();
        assert!(final_body.get("tools").is_none());
    }

    #[test]
    fn untrusted_system_content_is_rejected_before_anthropic_request() {
        let adapter = Anthropic::new("synthetic", "test-secret".into()).unwrap();
        let request = CompletionRequest {
            messages: vec![
                irmind_app::CompletionMessage::text(
                    MessageRole::System,
                    "<UNTRUSTED_test>case title</UNTRUSTED_test>".into(),
                ),
                irmind_app::CompletionMessage::text(MessageRole::User, "hello".into()),
            ],
            tools: Vec::new(),
            max_output_tokens: 64,
            remaining_case_tokens: 128,
        };
        assert!(adapter.body(&request).is_err());
        let safe = CompletionRequest {
            messages: vec![
                irmind_app::CompletionMessage::text(
                    MessageRole::System,
                    "Trusted IRMind instruction".into(),
                ),
                irmind_app::CompletionMessage::text(
                    MessageRole::User,
                    "<UNTRUSTED_test>case title</UNTRUSTED_test>".into(),
                ),
            ],
            ..request
        };
        let body = adapter.body(&safe).unwrap();
        assert_eq!(body["system"], "Trusted IRMind instruction");
        assert!(
            body["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("UNTRUSTED_test")
        );
    }

    #[test]
    fn recorded_two_round_native_tool_exchange_preserves_tool_use_id() {
        let adapter = Anthropic::new("synthetic", "test-secret".into()).unwrap();
        let tool_wire = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":8}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_recorded\",\"name\":\"evidence_search\",\"input\":{}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"query\\\":\\\"AssumeRole\\\"}\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":4}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        let final_wire = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":20}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"Found one event.\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        let (first, _) = stream::parse(tool_wire.as_bytes()).unwrap();
        let call = first.calls[0].clone();
        let request = CompletionRequest {
            messages: vec![
                irmind_app::CompletionMessage::text(MessageRole::User, "Find the event".into()),
                irmind_app::CompletionMessage::assistant_tools(first.text, first.calls),
                irmind_app::CompletionMessage::tool_result(
                    call.id().into(),
                    "<UNTRUSTED_test>one event</UNTRUSTED_test>".into(),
                ),
            ],
            tools: irmind_app::tool_catalog::catalog()[..1].to_vec(),
            max_output_tokens: 128,
            remaining_case_tokens: 1_000,
        };
        let body = adapter.body(&request).unwrap();
        assert_eq!(body["messages"][1]["content"][0]["id"], call.id());
        assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], call.id());
        let (final_answer, _) = stream::parse(final_wire.as_bytes()).unwrap();
        assert_eq!(final_answer.text, "Found one event.");
        assert!(final_answer.calls.is_empty());
    }

    #[test]
    fn registers_native_provider_under_its_own_module_id() {
        let adapter = Anthropic::new("claude-sonnet-4-6", "test-secret".into()).unwrap();
        let mut registry = ModuleRegistry::new();
        let mut config = ModuleConfig::new();
        config.insert_value("IRMIND_ANTHROPIC_MODEL", "claude-sonnet-4-6".into());
        config.insert_secret(
            "ANTHROPIC_API_KEY",
            SecretString::from("test-secret".to_owned()),
        );
        registry.register(Box::new(adapter), &config).unwrap();
        irmind_testkit::run_llm_contract(registry.llm(MODULE_ID).unwrap()).unwrap();
        irmind_testkit::run_http_safety_contract().unwrap();
        assert!(
            registry
                .llm(MODULE_ID)
                .unwrap()
                .descriptor()
                .contains("module=llm-anthropic")
        );
    }
}
