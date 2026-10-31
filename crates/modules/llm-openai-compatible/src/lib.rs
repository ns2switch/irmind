#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CompletionRequest, LlmPort, ModelStream,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_llm_chat_completions::{ChatCompletionsClient, ChatProfile};
use secrecy::ExposeSecret;

pub const MODULE_ID: &str = "llm-openai-compatible";
const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1/";

fn select_key(
    base_url: &str,
    configured: Option<String>,
    openai_default: Option<String>,
) -> Option<String> {
    configured.or_else(|| {
        (base_url.trim_end_matches('/') == DEFAULT_BASE_URL.trim_end_matches('/'))
            .then_some(openai_default)
            .flatten()
    })
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: MODULE_ID,
    version: "0.1.0",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[
        ConfigField {
            name: "IRMIND_LLM_BASE_URL",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_MODEL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_LLM_API_KEY",
            required: false,
            secret: true,
        },
        ConfigField {
            name: "OPENAI_API_KEY",
            required: false,
            secret: true,
        },
    ],
};

pub struct OpenAiCompatible(ChatCompletionsClient);

impl OpenAiCompatible {
    pub async fn list_models(
        provider: &str,
        base_url: &str,
        key: Option<&secrecy::SecretString>,
    ) -> Result<Vec<String>, AppError> {
        let secret = key.map(|value| value.expose_secret().to_owned());
        let _validated = ChatCompletionsClient::new(base_url, "synthetic", secret)?;
        let mut base = reqwest::Url::parse(base_url)
            .map_err(|_| AppError::Model("invalid model-list URL".into()))?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let url = if provider == "llm-anthropic" {
            base.join("v1/models")
        } else {
            base.join("models")
        }
        .map_err(|_| AppError::Model("invalid model-list endpoint".into()))?;
        let loopback = url.host_str().is_some_and(|host| {
            matches!(
                host.trim_matches(['[', ']']),
                "127.0.0.1" | "::1" | "localhost"
            )
        });
        let client = irmind_http::client_builder(std::time::Duration::from_secs(5), loopback)
            .build()
            .map_err(|_| AppError::Model("cannot create model-list client".into()))?;
        let request = client.get(url);
        let request = if provider == "llm-anthropic" {
            request.header("anthropic-version", "2023-06-01").header(
                "x-api-key",
                key.map_or("", secrecy::ExposeSecret::expose_secret),
            )
        } else if let Some(key) = key {
            request.bearer_auth(key.expose_secret())
        } else {
            request
        };
        let response = request
            .send()
            .await
            .map_err(|_| AppError::Model("model-list endpoint is unavailable".into()))?;
        if !response.status().is_success() {
            return Err(AppError::Model(format!(
                "model list returned HTTP {}",
                response.status()
            )));
        }
        let bytes =
            irmind_http::read_limited(response, 1_048_576, &irmind_app::CancellationToken::new())
                .await
                .map_err(|_| AppError::Model("model list is too large or unavailable".into()))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::Model("model list is invalid JSON".into()))?;
        let models = value
            .get("data")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| AppError::Model("model list has no data array".into()))?;
        let mut names = models
            .iter()
            .filter_map(|item| item.get("id").and_then(serde_json::Value::as_str))
            .filter(|id| id.len() <= 200 && !id.chars().any(char::is_control))
            .take(200)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        Ok(names)
    }

    pub async fn list_ollama_models(base_url: &str) -> Result<Vec<String>, AppError> {
        Ok(Self::ollama_metadata(base_url)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    async fn ollama_metadata(base_url: &str) -> Result<Vec<(String, u64)>, AppError> {
        let mut url = reqwest::Url::parse(base_url)
            .map_err(|_| AppError::Model("invalid Ollama URL".into()))?;
        if !url.host_str().is_some_and(|host| {
            matches!(
                host.trim_start_matches('[').trim_end_matches(']'),
                "127.0.0.1" | "::1" | "localhost"
            )
        }) || !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AppError::Model(
                "Ollama discovery requires a loopback HTTP or HTTPS URL".into(),
            ));
        }
        url.set_path("/api/tags");
        url.set_query(None);
        let client = irmind_http::client_builder(std::time::Duration::from_secs(5), true)
            .build()
            .map_err(|_| AppError::Model("cannot create Ollama client".into()))?;
        let response = client.get(url).send().await.map_err(|_| {
            AppError::Model("Ollama is not responding; start it with `ollama serve`".into())
        })?;
        if !response.status().is_success() {
            return Err(AppError::Model(format!(
                "Ollama model list returned HTTP {}",
                response.status()
            )));
        }
        let bytes =
            irmind_http::read_limited(response, 1_048_576, &irmind_app::CancellationToken::new())
                .await
                .map_err(|_| {
                    AppError::Model("Ollama model list is unavailable or too large".into())
                })?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::Model("Ollama returned an invalid model list".into()))?;
        let models = value
            .get("models")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| AppError::Model("Ollama returned no model list".into()))?;
        Ok(models
            .iter()
            .filter_map(|item| {
                let name = item.get("name")?.as_str()?;
                if name.is_empty() || name.len() > 200 || name.chars().any(char::is_control) {
                    return None;
                }
                Some((
                    name.to_owned(),
                    item.get("size")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                ))
            })
            .take(100)
            .collect())
    }

    /// Only offer local models whose Ollama metadata explicitly advertises tools.
    pub async fn list_ollama_tool_models(base_url: &str) -> Result<Vec<String>, AppError> {
        let names = Self::ollama_metadata(base_url).await?;
        let mut url = reqwest::Url::parse(base_url)
            .map_err(|_| AppError::Model("invalid Ollama URL".into()))?;
        url.set_path("/api/show");
        url.set_query(None);
        let client = irmind_http::client_builder(std::time::Duration::from_secs(5), true)
            .build()
            .map_err(|_| AppError::Model("cannot create Ollama client".into()))?;
        let mut supported = Vec::new();
        for (name, _) in names
            .into_iter()
            .filter(|(name, size)| *size > 0 && !name.ends_with(":cloud"))
            .take(25)
        {
            let Ok(response) = client
                .post(url.clone())
                .json(&serde_json::json!({"model": name}))
                .send()
                .await
            else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            let Ok(bytes) = irmind_http::read_limited(
                response,
                1_048_576,
                &irmind_app::CancellationToken::new(),
            )
            .await
            else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            if value
                .get("capabilities")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("tools")))
            {
                supported.push(name);
            }
        }
        Ok(supported)
    }

    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let base_url = config
            .value("IRMIND_LLM_BASE_URL")
            .unwrap_or(DEFAULT_BASE_URL);
        let model = config.required_value("IRMIND_MODEL")?;
        let key = select_key(
            base_url,
            config
                .secret("IRMIND_LLM_API_KEY")
                .map(|key| key.expose_secret().to_owned()),
            config
                .secret("OPENAI_API_KEY")
                .map(|key| key.expose_secret().to_owned()),
        );
        Self::new(base_url, model, key)
    }

    pub fn new(base_url: &str, model: &str, key: Option<String>) -> Result<Self, AppError> {
        Ok(Self(ChatCompletionsClient::new_with_profile(
            base_url,
            model,
            key,
            ChatProfile::OpenAi,
        )?))
    }
}

impl Module for OpenAiCompatible {
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

#[irmind_app::async_trait]
impl LlmPort for OpenAiCompatible {
    fn descriptor(&self) -> String {
        self.0.descriptor_for(MODULE_ID)
    }
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<ModelStream, AppError> {
        self.0.complete(request, cancel).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn compatible_and_anthropic_model_lists_use_bounded_authenticated_requests() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (provider, target, header) in [
            (MODULE_ID, "/v1/models", "authorization"),
            ("llm-anthropic", "/v1/models", "x-api-key"),
        ] {
            let server =
                irmind_testkit::MockServer::start(vec![irmind_testkit::MockResponse::json(
                    r#"{"data":[{"id":"synthetic-b"},{"id":"synthetic-a"}]}"#,
                )])
                .unwrap();
            let models = runtime
                .block_on(OpenAiCompatible::list_models(
                    provider,
                    &format!(
                        "{}{}",
                        server.origin(),
                        if provider == MODULE_ID { "v1/" } else { "" }
                    ),
                    Some(&secrecy::SecretString::from("synthetic/key")),
                ))
                .unwrap();
            assert_eq!(models, ["synthetic-a", "synthetic-b"]);
            let requests = server.finish().unwrap();
            assert_eq!(requests[0].target, target);
            assert!(requests[0].headers.contains_key(header));
        }
    }

    #[test]
    fn ollama_model_list_uses_bounded_loopback_request() {
        let server = irmind_testkit::MockServer::start(vec![irmind_testkit::MockResponse::json(
            r#"{"models":[{"name":"synthetic:latest"},{"name":"local:test"}]}"#,
        )])
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let models = runtime
            .block_on(OpenAiCompatible::list_ollama_models(&format!(
                "{}v1/",
                server.origin()
            )))
            .unwrap();
        assert_eq!(models, ["synthetic:latest", "local:test"]);
        let requests = server.finish().unwrap();
        assert_eq!(requests[0].target, "/api/tags");
        assert!(
            runtime
                .block_on(OpenAiCompatible::list_ollama_models(
                    "http://example.com/v1/"
                ))
                .is_err()
        );
    }

    #[test]
    fn demo_offers_only_local_ollama_models_with_tools() {
        let server = irmind_testkit::MockServer::start(vec![
            irmind_testkit::MockResponse::json(
                r#"{"models":[{"name":"tool-model","size":1024},{"name":"text-only","size":2048},{"name":"remote:cloud","size":0}]}"#,
            ),
            irmind_testkit::MockResponse::json(r#"{"capabilities":["completion","tools"]}"#),
            irmind_testkit::MockResponse::json(r#"{"capabilities":["completion"]}"#),
        ])
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let models = runtime
            .block_on(OpenAiCompatible::list_ollama_tool_models(&format!(
                "{}v1/",
                server.origin()
            )))
            .unwrap();
        assert_eq!(models, ["tool-model"]);
        let requests = server.finish().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.target.as_str())
                .collect::<Vec<_>>(),
            ["/api/tags", "/api/show", "/api/show"]
        );
    }

    #[test]
    fn openai_key_is_never_reused_for_custom_endpoint() {
        assert_eq!(
            select_key(DEFAULT_BASE_URL, None, Some("openai-secret".into())),
            Some("openai-secret".into())
        );
        assert_eq!(
            select_key(
                "https://other.example/v1/",
                None,
                Some("openai-secret".into())
            ),
            None
        );
        assert_eq!(
            select_key(
                "https://other.example/v1/",
                Some("own-key".into()),
                Some("openai-secret".into())
            ),
            Some("own-key".into())
        );
    }

    #[test]
    fn registers_compatible_provider_under_its_own_module_id() {
        let adapter =
            OpenAiCompatible::new("http://127.0.0.1:11434/v1/", "test-model", None).unwrap();
        let mut registry = ModuleRegistry::new();
        let mut config = ModuleConfig::new();
        config.insert_value("IRMIND_MODEL", "test-model".into());
        registry.register(Box::new(adapter), &config).unwrap();
        irmind_testkit::run_llm_contract(registry.llm(MODULE_ID).unwrap()).unwrap();
        let descriptor = registry.llm(MODULE_ID).unwrap().descriptor();
        assert!(descriptor.contains("module=llm-openai-compatible"));
        assert!(descriptor.contains("model=test-model"));
    }
}
