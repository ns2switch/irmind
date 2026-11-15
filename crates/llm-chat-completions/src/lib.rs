#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, CompletionMessage, CompletionRequest, LlmPort, MessageRole,
    ModelEvent, ModelStream, async_trait,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use std::net::IpAddr;

mod stream;

#[derive(Clone, Copy, Debug)]
pub enum ChatProfile {
    OpenAi,
    DeepSeek,
    OpenRouter,
}

pub struct ChatCompletionsClient {
    async_client: reqwest::Client,
    endpoint: reqwest::Url,
    key: Option<SecretString>,
    model: String,
    profile: ChatProfile,
    output: irmind_app::ModelOutputProfile,
}

impl ChatCompletionsClient {
    pub fn new(base_url: &str, model: &str, key: Option<String>) -> Result<Self, AppError> {
        Self::new_with_profile(base_url, model, key, ChatProfile::OpenAi)
    }

    pub fn new_with_profile(
        base_url: &str,
        model: &str,
        key: Option<String>,
        profile: ChatProfile,
    ) -> Result<Self, AppError> {
        let mut base = reqwest::Url::parse(base_url).map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::InvalidLLMBaseURL,
            ))
        })?;
        let loopback = base.host_str().is_some_and(|host| {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        });
        if (base.scheme() != "https" && !(base.scheme() == "http" && loopback))
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path().contains("..")
            || !base
                .path()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
        {
            return Err(AppError::Model(
                "LLM URL must be HTTPS or loopback HTTP without credentials, query or fragment"
                    .into(),
            ));
        }
        if model.trim().is_empty()
            || model.len() > 200
            || !model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::InvalidLLMModelID,
            )));
        }
        if key.as_ref().is_some_and(|value| value.trim().is_empty()) || (!loopback && key.is_none())
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::LLMAPIKeyIsRequiredForARemoteEndpoint,
            )));
        }
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let endpoint = base.join("chat/completions").map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::InvalidLLMChatEndpoint,
            ))
        })?;
        let async_client =
            irmind_http::client_builder(std::time::Duration::from_secs(90), loopback);
        let async_client = async_client.build().map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderHTTPClientUnavailable,
            ))
        })?;
        Ok(Self {
            async_client,
            endpoint: endpoint.clone(),
            key: key.map(SecretString::from),
            model: model.to_owned(),
            profile,
            output: output_profile(profile, endpoint.host_str(), model),
        })
    }

    pub fn with_output_configuration(
        mut self,
        maximum: Option<&str>,
        required: Option<&str>,
    ) -> Result<Self, AppError> {
        self.output = self.output.configured(maximum, required)?;
        Ok(self)
    }

    #[must_use]
    pub fn descriptor_for(&self, module_id: &str) -> String {
        format!(
            "module={module_id};model={};endpoint_sha256={}",
            self.model,
            irmind_app::hex(&irmind_app::sha256(self.endpoint.as_str().as_bytes()))
        )
    }
}

fn output_profile(
    profile: ChatProfile,
    host: Option<&str>,
    model: &str,
) -> irmind_app::ModelOutputProfile {
    // Exact identities only. Specifications: docs/configuration.md#model-output.
    let maximum = match (profile, host, model) {
        (
            ChatProfile::OpenAi,
            Some("api.openai.com"),
            "gpt-4.1" | "gpt-4.1-2025-04-14" | "gpt-4.1-mini" | "gpt-4.1-mini-2025-04-14",
        ) => Some(32_768),
        (ChatProfile::OpenAi, Some("api.openai.com"), "gpt-4o") => Some(16_384),
        (
            ChatProfile::OpenAi,
            Some("api.openai.com"),
            "gpt-5" | "gpt-5-2025-08-07" | "gpt-5.2" | "gpt-5.4" | "gpt-5.5" | "gpt-6-astra"
            | "gpt-6.1-sol" | "gpt-6.1-terra" | "gpt-6-luna",
        ) => Some(128_000),
        (
            ChatProfile::DeepSeek,
            Some("api.deepseek.com"),
            "deepseek-flash"
            | "deepseek-v4-pro"
            | "deepseek-v4-flash"
            | "deepseek-v4-flash-vision-exp",
        ) => Some(393_216),
        _ => None,
    };
    irmind_app::ModelOutputProfile {
        maximum_output_tokens: maximum.and_then(std::num::NonZeroU32::new),
        parameter_requirement: irmind_app::OutputParameterRequirement::Optional,
    }
}

impl ChatCompletionsClient {
    fn request_body(&self, request: &CompletionRequest) -> serde_json::Value {
        let tools = request
            .tools
            .iter()
            .map(|spec| {
                json!({"type":"function","function":{
                    "name":spec.name,"description":spec.description,"parameters":spec.parameters
                }})
            })
            .collect::<Vec<_>>();
        let messages = request
            .messages
            .iter()
            .map(encode_message)
            .collect::<Vec<_>>();
        let limit = self
            .output
            .maximum_output_tokens
            .map(std::num::NonZeroU32::get);
        let mut body = json!({"model":self.model,"messages":messages,"stream":true,
            "stream_options":{"include_usage":true}});
        if !tools.is_empty() {
            body["tools"] = json!(tools);
            body["tool_choice"] = json!("auto");
        }
        match self.profile {
            ChatProfile::OpenAi => {
                if let Some(limit) = limit {
                    let field = if self.endpoint.host_str() == Some("api.openai.com") {
                        "max_completion_tokens"
                    } else {
                        "max_tokens"
                    };
                    body[field] = json!(limit);
                }
                body["parallel_tool_calls"] = json!(false);
                body["store"] = json!(false);
            }
            ChatProfile::DeepSeek => {
                if let Some(limit) = limit {
                    body["max_tokens"] = json!(limit);
                }
                if !request.tools.is_empty()
                    || request
                        .messages
                        .iter()
                        .any(|message| !message.tool_calls.is_empty())
                {
                    body["thinking"] = json!({"type":"disabled"});
                }
            }
            ChatProfile::OpenRouter => {
                if let Some(limit) = limit {
                    body["max_completion_tokens"] = json!(limit);
                }
                body["parallel_tool_calls"] = json!(false);
            }
        }
        body
    }
}

fn encode_message(message: &CompletionMessage) -> serde_json::Value {
    match message.role {
        MessageRole::Tool => json!({
            "role":"tool", "tool_call_id":message.tool_call_id, "content":message.content
        }),
        MessageRole::Assistant if !message.tool_calls.is_empty() => {
            let calls = message
                .tool_calls
                .iter()
                .map(|call| {
                    json!({
                        "id":call.id(),"type":"function","function":{
                            "name":call.proposal().tool.as_str(),
                            "arguments":call.arguments_json()
                        }
                    })
                })
                .collect::<Vec<_>>();
            json!({"role":"assistant","content":message.content,"tool_calls":calls})
        }
        role => {
            let role = match role {
                MessageRole::System => "system",
                MessageRole::User => "user",
                MessageRole::Assistant => "assistant",
                MessageRole::Tool => "tool",
            };
            json!({"role":role,"content":message.content})
        }
    }
}

#[async_trait]
impl LlmPort for ChatCompletionsClient {
    fn output_profile(&self) -> irmind_app::ModelOutputProfile {
        self.output
    }
    fn descriptor(&self) -> String {
        self.descriptor_for("llm-chat-completions")
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.output.parameter_value()?;
        request.validate()?;
        let body = self.request_body(&request);
        let mut http_request = self.async_client.post(self.endpoint.clone());
        if let Some(key) = &self.key {
            http_request = http_request.bearer_auth(key.expose_secret());
        }
        let mut response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = http_request.json(&body).send() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterModel(irmind_app::AdapterModelError::ProviderRequestFailed)))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Model(format!(
                "provider status {}",
                response.status()
            )));
        }
        let cancel = cancel.clone();
        Ok(Box::pin(async_stream::try_stream! {
            let mut raw = Vec::new();
            let mut preview = stream::TextPreview::default();
            loop {
                let chunk = tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(AppError::Cancelled),
                    result = response.chunk() => result.map_err(|_| AppError::Fixed(irmind_app::FixedAppError::AdapterModel(irmind_app::AdapterModelError::ProviderResponseFailed))),
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
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    #[tokio::test]
    async fn model_maxima_are_not_request_budgets_and_unknown_optional_is_omitted() {
        let request = CompletionRequest {
            messages: vec![CompletionMessage::text(
                MessageRole::User,
                "Synthetic".into(),
            )],
            tools: Vec::new(),
        };
        let local =
            ChatCompletionsClient::new("http://127.0.0.1:11434/v1/", "gpt-4.1", None).unwrap();
        assert!(
            local
                .request_body(&request)
                .get("max_completion_tokens")
                .is_none()
        );
        let known = ChatCompletionsClient::new(
            "https://api.openai.com/v1/",
            "gpt-4.1",
            Some("synthetic".into()),
        )
        .unwrap();
        assert_eq!(
            known.request_body(&request)["max_completion_tokens"],
            32_768
        );
        let required = local.with_output_configuration(None, Some("true")).unwrap();
        let error = required
            .complete(request, &CancellationToken::new())
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("/settings model"));
    }

    #[test]
    fn endpoint_is_explicit_and_local_http_requires_loopback() {
        let local =
            ChatCompletionsClient::new("http://127.0.0.1:11434/v1", "local-model", None).unwrap();
        assert_eq!(
            local.endpoint.as_str(),
            "http://127.0.0.1:11434/v1/chat/completions"
        );
        assert!(local.descriptor().contains("model=local-model"));
        assert!(local.descriptor().contains("endpoint_sha256="));
        assert!(!local.descriptor().contains("127.0.0.1"));
        irmind_testkit::run_llm_contract(&local).unwrap();
        irmind_testkit::run_http_safety_contract().unwrap();
        let ipv6 = ChatCompletionsClient::new("http://[::1]:11434/v1/", "local-model", None);
        assert!(ipv6.is_ok());
        assert!(
            ChatCompletionsClient::new("https://localhost:11434/v1/", "local-model", None).is_ok()
        );
        assert!(
            ChatCompletionsClient::new("http://example.com/v1/", "x", Some("key".into())).is_err()
        );
        assert!(
            ChatCompletionsClient::new(
                "https://user:pass@example.com/v1/",
                "x",
                Some("key".into())
            )
            .is_err()
        );
        assert!(
            ChatCompletionsClient::new("https://example.com/v1/?debug=1", "x", Some("key".into()))
                .is_err()
        );
        assert!(ChatCompletionsClient::new("https://example.com/v1/", "x", None).is_err());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn chat_profiles_send_supported_fields_and_parse_complete_streams() {
        for profile in [
            ChatProfile::OpenAi,
            ChatProfile::DeepSeek,
            ChatProfile::OpenRouter,
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut received = Vec::new();
                let header_end = loop {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    received.extend_from_slice(&chunk[..count]);
                    if let Some(index) = received.windows(4).position(|part| part == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let header = std::str::from_utf8(&received[..header_end]).unwrap();
                assert!(header.starts_with("POST /v1/chat/completions HTTP/1.1"));
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap();
                while received.len() < header_end + length {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    received.extend_from_slice(&chunk[..count]);
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&received[header_end..header_end + length]).unwrap();
                let wire = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n";
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire}", wire.len()).unwrap();
                body
            });
            let adapter = ChatCompletionsClient::new_with_profile(
                &format!("http://{address}/v1/"),
                "model",
                None,
                profile,
            )
            .unwrap()
            .with_output_configuration(Some("128000"), None)
            .unwrap();
            let catalog = irmind_app::tool_catalog::catalog();
            let events = adapter
                .complete(
                    CompletionRequest {
                        messages: vec![irmind_app::CompletionMessage {
                            role: MessageRole::User,
                            content: "case".into(),
                            tool_calls: Vec::new(),
                            tool_call_id: None,
                        }],
                        tools: catalog[..1].to_vec(),
                    },
                    &CancellationToken::new(),
                )
                .await
                .unwrap();
            let (answer, usage) =
                irmind_app::collect_model_stream(events, &CancellationToken::new())
                    .await
                    .unwrap();
            assert_eq!(answer.text, "ok");
            assert_eq!(usage.unwrap().output_tokens, 2);
            let body = server.join().unwrap();
            assert_eq!(body["tools"][0]["function"]["name"], "evidence_search");
            assert_eq!(body["stream_options"]["include_usage"], true);
            match profile {
                ChatProfile::OpenAi => {
                    assert_eq!(body["store"], false);
                    assert_eq!(body["max_tokens"], 128_000);
                }
                ChatProfile::DeepSeek => {
                    assert_eq!(body["max_tokens"], 128_000);
                    assert!(body.get("store").is_none());
                    assert!(body.get("parallel_tool_calls").is_none());
                }
                ChatProfile::OpenRouter => {
                    assert_eq!(body["max_completion_tokens"], 128_000);
                    assert!(body.get("store").is_none());
                }
            }
        }
    }

    #[test]
    fn chat_profiles_preserve_tool_call_ids_and_disable_tools_for_final_summary() {
        let proposal = irmind_app::ProposedCall {
            tool: irmind_app::Tool::EvidenceSearch,
            args: std::collections::BTreeMap::from([("query".into(), "AssumeRole".into())]),
        };
        let call = irmind_app::ModelToolCall::from_proposal("call_synthetic", proposal).unwrap();
        for profile in [
            ChatProfile::OpenAi,
            ChatProfile::DeepSeek,
            ChatProfile::OpenRouter,
        ] {
            let adapter = ChatCompletionsClient::new_with_profile(
                "http://127.0.0.1:11434/v1/",
                "synthetic",
                None,
                profile,
            )
            .unwrap();
            let messages = vec![
                CompletionMessage::text(MessageRole::User, "Find the event".into()),
                CompletionMessage::assistant_tools("Searching".into(), vec![call.clone()]),
                CompletionMessage::tool_result(
                    "call_synthetic".into(),
                    "<UNTRUSTED_test>event</UNTRUSTED_test>".into(),
                ),
            ];
            let request = CompletionRequest {
                messages,
                tools: irmind_app::tool_catalog::catalog()[..1].to_vec(),
            };
            request.validate().unwrap();
            let body = adapter.request_body(&request);
            assert_eq!(body["messages"][1]["tool_calls"][0]["id"], "call_synthetic");
            assert_eq!(
                body["messages"][1]["tool_calls"][0]["function"]["arguments"],
                call.arguments_json()
            );
            assert_eq!(body["messages"][2]["role"], "tool");
            assert_eq!(body["messages"][2]["tool_call_id"], "call_synthetic");
            if matches!(profile, ChatProfile::DeepSeek) {
                assert_eq!(body["thinking"]["type"], "disabled");
            }
            let mut final_request = request.clone();
            final_request.tools.clear();
            let final_body = adapter.request_body(&final_request);
            assert!(final_body.get("tools").is_none());
            assert!(final_body.get("tool_choice").is_none());
            if matches!(profile, ChatProfile::DeepSeek) {
                assert_eq!(final_body["thinking"]["type"], "disabled");
            }
        }
    }

    #[test]
    fn recorded_two_round_tool_exchange_works_for_every_chat_profile() {
        let tool_wire = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_recorded\",\"type\":\"function\",\"function\":{\"name\":\"evidence_search\",\"arguments\":\"{\\\"query\\\":\\\"AssumeRole\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":4}}\n\n",
            "data: [DONE]\n\n"
        );
        let final_wire = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Found one event.\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":5}}\n\n",
            "data: [DONE]\n\n"
        );
        for profile in [
            ChatProfile::OpenAi,
            ChatProfile::DeepSeek,
            ChatProfile::OpenRouter,
        ] {
            let adapter = ChatCompletionsClient::new_with_profile(
                "http://127.0.0.1:11434/v1/",
                "synthetic",
                None,
                profile,
            )
            .unwrap();
            let (first, _) = stream::parse(tool_wire.as_bytes()).unwrap();
            let call = first.calls[0].clone();
            let request = CompletionRequest {
                messages: vec![
                    CompletionMessage::text(MessageRole::User, "Find the event".into()),
                    CompletionMessage::assistant_tools(first.text, first.calls),
                    CompletionMessage::tool_result(
                        call.id().into(),
                        "<UNTRUSTED_test>one event</UNTRUSTED_test>".into(),
                    ),
                ],
                tools: irmind_app::tool_catalog::catalog()[..1].to_vec(),
            };
            request.validate().unwrap();
            let body = adapter.request_body(&request);
            assert_eq!(body["messages"][1]["tool_calls"][0]["id"], call.id());
            assert_eq!(body["messages"][2]["tool_call_id"], call.id());
            let (final_answer, _) = stream::parse(final_wire.as_bytes()).unwrap();
            assert_eq!(final_answer.text, "Found one event.");
            assert!(final_answer.calls.is_empty());
        }
    }
}
