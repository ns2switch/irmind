#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, CompletionRequest, LlmPort, MessageRole, ModelEvent, ModelStream,
    async_trait,
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
        let mut base = reqwest::Url::parse(base_url)
            .map_err(|_| AppError::Model("invalid LLM base URL".into()))?;
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
            return Err(AppError::Model("invalid LLM model ID".into()));
        }
        if key.as_ref().is_some_and(|value| value.trim().is_empty()) || (!loopback && key.is_none())
        {
            return Err(AppError::Model(
                "LLM API key is required for a remote endpoint".into(),
            ));
        }
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let endpoint = base
            .join("chat/completions")
            .map_err(|_| AppError::Model("invalid LLM chat endpoint".into()))?;
        let mut async_client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none());
        if loopback {
            async_client = async_client.no_proxy();
        }
        let async_client = async_client
            .build()
            .map_err(|_| AppError::Model("provider HTTP client unavailable".into()))?;
        Ok(Self {
            async_client,
            endpoint,
            key: key.map(SecretString::from),
            model: model.to_owned(),
            profile,
        })
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

#[async_trait]
impl LlmPort for ChatCompletionsClient {
    fn descriptor(&self) -> String {
        self.descriptor_for("llm-chat-completions")
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        if request.max_output_tokens == 0 || request.remaining_case_tokens == 0 {
            return Err(AppError::Model("model token budget is empty".into()));
        }
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
            .map(|message| {
                let role = match message.role {
                    MessageRole::System => "system",
                    MessageRole::User => "user",
                    MessageRole::Assistant => "assistant",
                    MessageRole::Tool => "tool",
                };
                json!({"role":role,"content":message.content})
            })
            .collect::<Vec<_>>();
        let limit = u64::from(request.max_output_tokens).min(request.remaining_case_tokens);
        let mut body = json!({"model":self.model,"messages":messages,
            "tools":tools,"tool_choice":"auto","stream":true,
            "stream_options":{"include_usage":true}});
        match self.profile {
            ChatProfile::OpenAi => {
                body["max_completion_tokens"] = json!(limit);
                body["parallel_tool_calls"] = json!(false);
                body["store"] = json!(false);
            }
            ChatProfile::DeepSeek => body["max_tokens"] = json!(limit),
            ChatProfile::OpenRouter => {
                body["max_completion_tokens"] = json!(limit);
                body["parallel_tool_calls"] = json!(false);
            }
        }
        let mut http_request = self.async_client.post(self.endpoint.clone());
        if let Some(key) = &self.key {
            http_request = http_request.bearer_auth(key.expose_secret());
        }
        let mut response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = http_request.json(&body).send() => result.map_err(|_| AppError::Model("provider request failed".into()))?,
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
            loop {
                let chunk = tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(AppError::Cancelled),
                    result = response.chunk() => result.map_err(|_| AppError::Model("provider response failed".into())),
                }?;
                let Some(chunk) = chunk else { break };
                if raw.len().saturating_add(chunk.len()) > 2_000_000 {
                    Err(AppError::Model("provider stream exceeds 2 MB".into()))?;
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
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

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
            .unwrap();
            let catalog = irmind_app::tool_catalog::catalog();
            let events = adapter
                .complete(
                    CompletionRequest {
                        messages: vec![irmind_app::CompletionMessage {
                            role: MessageRole::User,
                            content: "case".into(),
                        }],
                        tools: catalog[..1].to_vec(),
                        max_output_tokens: 2048,
                        remaining_case_tokens: 10_000,
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
                    assert_eq!(body["max_completion_tokens"], 2048);
                }
                ChatProfile::DeepSeek => {
                    assert_eq!(body["max_tokens"], 2048);
                    assert!(body.get("store").is_none());
                    assert!(body.get("parallel_tool_calls").is_none());
                }
                ChatProfile::OpenRouter => {
                    assert_eq!(body["max_completion_tokens"], 2048);
                    assert!(body.get("store").is_none());
                }
            }
        }
    }
}
