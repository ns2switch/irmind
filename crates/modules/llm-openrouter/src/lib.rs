#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CompletionRequest, LlmPort, ModelStream,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_llm_chat_completions::{ChatCompletionsClient, ChatProfile};
use secrecy::ExposeSecret;

pub const MODULE_ID: &str = "llm-openrouter";
const BASE_URL: &str = "https://openrouter.ai/api/v1/";

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: MODULE_ID,
    version: "0.1.0",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[
        ConfigField {
            name: "IRMIND_OPENROUTER_BASE_URL",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_OPENROUTER_MODEL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "OPENROUTER_API_KEY",
            required: true,
            secret: true,
        },
    ],
};

pub struct OpenRouter(ChatCompletionsClient);

impl OpenRouter {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let model = config.required_value("IRMIND_OPENROUTER_MODEL")?;
        let key = config
            .required_secret("OPENROUTER_API_KEY")?
            .expose_secret()
            .to_owned();
        Ok(Self(ChatCompletionsClient::new_with_profile(
            config
                .value("IRMIND_OPENROUTER_BASE_URL")
                .unwrap_or(BASE_URL),
            model,
            Some(key),
            ChatProfile::OpenRouter,
        )?))
    }
}

impl Module for OpenRouter {
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
impl LlmPort for OpenRouter {
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
    fn registers_provider_under_its_own_module_id() {
        let inner = ChatCompletionsClient::new_with_profile(
            "http://127.0.0.1:11434/v1/",
            "test-model",
            None,
            ChatProfile::OpenRouter,
        )
        .unwrap();
        let mut registry = ModuleRegistry::new();
        let mut config = ModuleConfig::new();
        config.insert_value("IRMIND_OPENROUTER_MODEL", "test-model".into());
        config.insert_secret(
            "OPENROUTER_API_KEY",
            secrecy::SecretString::from("test-secret".to_owned()),
        );
        registry
            .register(Box::new(OpenRouter(inner)), &config)
            .unwrap();
        irmind_testkit::run_llm_contract(registry.llm(MODULE_ID).unwrap()).unwrap();
        let descriptor = registry.llm(MODULE_ID).unwrap().descriptor();
        assert!(descriptor.contains(&format!("module={MODULE_ID}")));
        assert!(descriptor.contains("model=test-model"));
    }
}
