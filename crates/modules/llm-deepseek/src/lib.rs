#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CompletionRequest, LlmPort, ModelResponse, ModelUsage,
    modules::{ConfigField, Module, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_llm_chat_completions::{ChatCompletionsClient, ChatProfile};

pub const MODULE_ID: &str = "llm-deepseek";
const BASE_URL: &str = "https://api.deepseek.com/";

static MANIFEST: ModuleManifest = ModuleManifest {
    id: MODULE_ID,
    version: "0.1.0",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[
        ConfigField {
            name: "IRMIND_DEEPSEEK_MODEL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "DEEPSEEK_API_KEY",
            required: true,
            secret: true,
        },
    ],
};

pub struct DeepSeek(ChatCompletionsClient);

impl DeepSeek {
    pub fn from_env() -> Result<Self, AppError> {
        let model = std::env::var("IRMIND_DEEPSEEK_MODEL")
            .map_err(|_| AppError::Model("IRMIND_DEEPSEEK_MODEL is required".into()))?;
        let key = std::env::var("DEEPSEEK_API_KEY")
            .map_err(|_| AppError::Model("DEEPSEEK_API_KEY is required".into()))?;
        Ok(Self(ChatCompletionsClient::new_with_profile(
            BASE_URL,
            &model,
            Some(key),
            ChatProfile::DeepSeek,
        )?))
    }
}

impl Module for DeepSeek {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_llm(MODULE_ID, self)
    }
}

impl LlmPort for DeepSeek {
    fn descriptor(&self) -> String {
        self.0.descriptor_for(MODULE_ID)
    }
    fn complete(&self, context: &str) -> Result<ModelResponse, AppError> {
        self.0.complete(context)
    }
    fn complete_with_usage(
        &self,
        context: &str,
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        self.0.complete_with_usage(context)
    }
    fn complete_request(
        &self,
        request: &CompletionRequest<'_>,
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        self.0.complete_request(request)
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
            ChatProfile::DeepSeek,
        )
        .unwrap();
        let mut registry = ModuleRegistry::new();
        registry.register(Box::new(DeepSeek(inner))).unwrap();
        let descriptor = registry.llm(MODULE_ID).unwrap().descriptor();
        assert!(descriptor.contains(&format!("module={MODULE_ID}")));
        assert!(descriptor.contains("model=test-model"));
    }
}
