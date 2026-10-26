#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, CompletionRequest, LlmPort, MessageRole, ModelEvent, ModelStream,
    async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

mod stream;

pub const MODULE_ID: &str = "llm-anthropic";
const ENDPOINT: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2026-10-21";

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: MODULE_ID,
    version: "0.1.0",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[
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
    key: SecretString,
    model: String,
}

impl Anthropic {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let model = config.required_value("IRMIND_ANTHROPIC_MODEL")?;
        let key = config
            .required_secret("ANTHROPIC_API_KEY")?
            .expose_secret()
            .to_owned();
        Self::new(model, key)
    }

    pub fn new(model: &str, key: String) -> Result<Self, AppError> {
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
            key: SecretString::from(key),
            model: model.to_owned(),
        })
    }

    fn body(&self, request: &CompletionRequest) -> Result<serde_json::Value, AppError> {
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
        let system = request
            .messages
            .iter()
            .filter(|message| message.role == MessageRole::System)
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let messages = request
            .messages
            .iter()
            .filter(|message| message.role != MessageRole::System)
            .map(|message| {
                json!({"role":match message.role {
                MessageRole::Assistant => "assistant", _ => "user"
            }, "content":message.content})
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "model": self.model,
            "max_tokens": u64::from(request.max_output_tokens).min(request.remaining_case_tokens),
            "system": system,
            "messages": messages,
            "tools": tools,
            "tool_choice": {"type":"auto","disable_parallel_tool_use":true},
            "stream": true,
        }))
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
            irmind_app::hex(&irmind_app::sha256(ENDPOINT.as_bytes()))
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
            result = self.async_client.post(ENDPOINT)
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
