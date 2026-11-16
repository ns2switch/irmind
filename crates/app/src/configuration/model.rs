use super::{ModuleManifest, ModulePort, PersistentConfig, invalid, manifest, valid_value};
use crate::AppError;
use serde::{Deserialize, Serialize};
use url::Url;

/// One analyst-selected, non-secret model draft. Field names come from the
/// provider, never from form input; all values are staged before signing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfiguration {
    pub module: String,
    pub base_url: String,
    pub model: String,
    pub maximum_output_tokens: Option<u32>,
    pub output_required: bool,
}

impl ModelConfiguration {
    pub fn parameter_fields(&self) -> Result<[&'static str; 4], AppError> {
        let (url, model) = match self.module.as_str() {
            "llm-openai-compatible" => ("IRMIND_LLM_BASE_URL", "IRMIND_MODEL"),
            "llm-anthropic" => ("IRMIND_ANTHROPIC_BASE_URL", "IRMIND_ANTHROPIC_MODEL"),
            "llm-deepseek" => ("IRMIND_DEEPSEEK_BASE_URL", "IRMIND_DEEPSEEK_MODEL"),
            "llm-openrouter" => ("IRMIND_OPENROUTER_BASE_URL", "IRMIND_OPENROUTER_MODEL"),
            _ => return Err(invalid()),
        };
        Ok([
            url,
            model,
            "IRMIND_MODEL_MAX_OUTPUT_TOKENS",
            "IRMIND_MODEL_OUTPUT_REQUIRED",
        ])
    }

    pub fn validate(&self) -> Result<(), AppError> {
        let fields = self.parameter_fields()?;
        if !valid_value(fields[0], &self.base_url) || !valid_value(fields[1], &self.model) {
            return Err(AppError::Policy("Enter a valid model name and an HTTPS base URL (HTTP is allowed only for loopback), without credentials or query parameters".into()));
        }
        if self.maximum_output_tokens == Some(0) {
            return Err(AppError::Model(
                "Set a positive integer model output maximum in /settings model".into(),
            ));
        }
        let url = Url::parse(&self.base_url).map_err(|_| invalid())?;
        let host = url.host_str().ok_or_else(invalid)?;
        let expected = match host {
            "api.anthropic.com" => Some("llm-anthropic"),
            "api.deepseek.com" => Some("llm-deepseek"),
            "openrouter.ai" => Some("llm-openrouter"),
            "api.openai.com"
            | "api.mistral.ai"
            | "api.groq.com"
            | "generativelanguage.googleapis.com"
            | "api.x.ai"
            | "api.together.ai" => Some("llm-openai-compatible"),
            _ => None, // Explicit custom endpoints/local servers retain custom model IDs.
        };
        if expected.is_some_and(|id| id != self.module) {
            return Err(AppError::Policy("The base URL belongs to a different provider; select its matching provider in /settings model".into()));
        }
        let wrong_model = match host {
            "api.anthropic.com" => !self.model.starts_with("claude-"),
            "api.deepseek.com" => !self.model.starts_with("deepseek-"),
            "api.openai.com" => {
                self.model.starts_with("claude-")
                    || self.model.starts_with("deepseek-")
                    || self.model.contains('/')
            }
            _ => false, // Gateways such as OpenRouter intentionally serve multiple vendors.
        };
        if wrong_model {
            return Err(AppError::Policy("The model ID does not match this provider endpoint; choose its model in /settings model".into()));
        }
        if self.module == "llm-anthropic" && !self.output_required {
            return Err(AppError::Model(
                "Anthropic requires the output parameter; keep that requirement enabled".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn apply(
        &self,
        next: &mut PersistentConfig,
        manifests: &[&ModuleManifest],
    ) -> Result<(), AppError> {
        self.validate()?;
        let schema = manifest(&self.module, manifests)?;
        let fields = self.parameter_fields()?;
        if !schema.ports.contains(&ModulePort::Llm)
            || !fields.iter().all(|name| {
                schema
                    .config
                    .iter()
                    .any(|field| field.name == *name && !field.secret)
            })
        {
            return Err(invalid());
        }
        let values = &mut next.modules.entry(self.module.clone()).or_default().values;
        values.insert(fields[0].into(), self.base_url.clone());
        values.insert(fields[1].into(), self.model.clone());
        if let Some(maximum) = self.maximum_output_tokens {
            values.insert(fields[2].into(), maximum.to_string());
        } else {
            values.remove(fields[2]);
        }
        values.insert(fields[3].into(), self.output_required.to_string());
        next.llm_module = Some(self.module.clone());
        Ok(())
    }
}
