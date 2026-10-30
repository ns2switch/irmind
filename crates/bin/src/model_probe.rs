use anyhow::{Result, anyhow};
use irmind_app::{
    CancellationToken, CompletionMessage, CompletionRequest, LlmPort, MessageRole, SecretBackend,
    collect_model_stream, modules::ModuleConfig,
};
use secrecy::{ExposeSecret as _, SecretString};

pub(super) fn list_ollama_models(base_url: &str) -> Result<Vec<String>> {
    let runtime = runtime()?;
    runtime
        .block_on(irmind_mod_llm_openai_compatible::OpenAiCompatible::list_ollama_models(base_url))
        .map_err(Into::into)
}

pub(super) fn list_provider_models(
    provider: &str,
    base_url: &str,
    key: Option<&SecretString>,
) -> Result<Vec<String>> {
    let runtime = runtime()?;
    if base_url.starts_with("http://127.0.0.1:11434/")
        || base_url.starts_with("https://127.0.0.1:11434/")
    {
        return list_ollama_models(base_url);
    }
    runtime
        .block_on(
            irmind_mod_llm_openai_compatible::OpenAiCompatible::list_models(
                provider, base_url, key,
            ),
        )
        .map_err(Into::into)
}

pub(super) fn test_model_connection(
    provider: &str,
    base_url: &str,
    model: &str,
    supplied_key: Option<&SecretString>,
    secrets: &dyn SecretBackend,
) -> Result<String> {
    let port = construct_port(provider, base_url, model, supplied_key, secrets)?;
    let cancel = CancellationToken::new();
    let request = CompletionRequest {
        messages: vec![CompletionMessage {
            role: MessageRole::User,
            content:
                "Reply with OK. This is a synthetic connection test; no case data is included."
                    .into(),
        }],
        tools: Vec::new(),
        max_output_tokens: 8,
        remaining_case_tokens: 8,
    };
    let runtime = runtime()?;
    runtime.block_on(async {
        let events = port.complete(request, &cancel).await?;
        let _ = collect_model_stream(events, &cancel).await?;
        Ok::<(), irmind_app::AppError>(())
    })?;
    Ok("Connection succeeded with synthetic text; no case data was sent".into())
}

fn construct_port(
    provider: &str,
    base_url: &str,
    model: &str,
    supplied_key: Option<&SecretString>,
    secrets: &dyn SecretBackend,
) -> Result<Box<dyn LlmPort>> {
    if provider == "llm-openai-compatible" {
        let key = if let Some(value) = supplied_key {
            Some(value.expose_secret().to_owned())
        } else {
            match secrets.get("IRMIND_LLM_API_KEY") {
                Ok(value) => Some(value.expose_secret().to_owned()),
                Err(irmind_app::AppError::SecretMissing) => None,
                Err(error) => return Err(error.into()),
            }
        };
        if ![
            "http://127.0.0.1:",
            "http://localhost:",
            "http://[::1]:",
            "https://127.0.0.1:",
            "https://localhost:",
            "https://[::1]:",
        ]
        .iter()
        .any(|prefix| base_url.starts_with(prefix))
            && key.is_none()
        {
            return Err(anyhow!(
                "remote model requires an API key in the configured SecretBackend"
            ));
        }
        return Ok(Box::new(
            irmind_mod_llm_openai_compatible::OpenAiCompatible::new(base_url, model, key)?,
        ));
    }
    let mut config = ModuleConfig::new();
    let (model_field, base_field, key_field) = match provider {
        "llm-anthropic" => (
            "IRMIND_ANTHROPIC_MODEL",
            "IRMIND_ANTHROPIC_BASE_URL",
            "ANTHROPIC_API_KEY",
        ),
        "llm-deepseek" => (
            "IRMIND_DEEPSEEK_MODEL",
            "IRMIND_DEEPSEEK_BASE_URL",
            "DEEPSEEK_API_KEY",
        ),
        "llm-openrouter" => (
            "IRMIND_OPENROUTER_MODEL",
            "IRMIND_OPENROUTER_BASE_URL",
            "OPENROUTER_API_KEY",
        ),
        _ => return Err(anyhow!("unknown or uncompiled model provider")),
    };
    config.insert_value(model_field, model.into());
    config.insert_value(base_field, base_url.into());
    let key = supplied_key
        .cloned()
        .map_or_else(|| secrets.get(key_field), Ok)?;
    config.insert_secret(key_field, key);
    match provider {
        #[cfg(feature = "llm-anthropic")]
        "llm-anthropic" => Ok(Box::new(irmind_mod_llm_anthropic::Anthropic::from_config(
            &config,
        )?)),
        #[cfg(feature = "llm-deepseek")]
        "llm-deepseek" => Ok(Box::new(irmind_mod_llm_deepseek::DeepSeek::from_config(
            &config,
        )?)),
        #[cfg(feature = "llm-openrouter")]
        "llm-openrouter" => Ok(Box::new(
            irmind_mod_llm_openrouter::OpenRouter::from_config(&config)?,
        )),
        _ => Err(anyhow!("model provider is not compiled into this binary")),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
