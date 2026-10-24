#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CompletionRequest, LlmPort, ModelResponse, ModelUsage,
    modules::{ConfigField, Module, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_llm_chat_completions::{ChatCompletionsClient, ChatProfile};

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

static MANIFEST: ModuleManifest = ModuleManifest {
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
    pub fn from_env() -> Result<Self, AppError> {
        let base_url =
            std::env::var("IRMIND_LLM_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.into());
        let model = std::env::var("IRMIND_MODEL")
            .map_err(|_| AppError::Model("IRMIND_MODEL is required".into()))?;
        let key = select_key(
            &base_url,
            std::env::var("IRMIND_LLM_API_KEY").ok(),
            std::env::var("OPENAI_API_KEY").ok(),
        );
        Self::new(&base_url, &model, key)
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
    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_llm(MODULE_ID, self)
    }
}

impl LlmPort for OpenAiCompatible {
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
        registry.register(Box::new(adapter)).unwrap();
        let descriptor = registry.llm(MODULE_ID).unwrap().descriptor();
        assert!(descriptor.contains("module=llm-openai-compatible"));
        assert!(descriptor.contains("model=test-model"));
    }
}
