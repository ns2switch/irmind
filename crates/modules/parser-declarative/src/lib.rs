#![forbid(unsafe_code)]
mod indexed;
mod pipeline;

use irmind_app::AppError;
use regex::Regex;

mod config;
mod detection;
mod input;
mod json_fields;
mod mapping;
mod module;
mod ports;
pub use module::{DeclarativeCompiler, DeclarativeModule, MANIFEST};
mod parse;

/// A validated definition and bounded, precompiled linear-time expressions.
/// It performs no I/O and is not installed in the application by constructing it.
pub struct DeclarativeParser {
    definition: config::Definition,
    id: String,
    version: String,
    timestamp_context: String,
    input_regex: Option<Regex>,
    detection_regex: Option<Regex>,
}

impl std::fmt::Debug for DeclarativeParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclarativeParser")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl DeclarativeParser {
    pub fn from_toml(text: &str) -> Result<Self, AppError> {
        let definition = config::Definition::decode(text)?;
        mapping::timezone(&definition.timestamp.default_timezone)?;
        if chrono::format::StrftimeItems::new(&definition.timestamp.format)
            .any(|item| matches!(item, chrono::format::Item::Error))
            && !matches!(definition.timestamp.format.as_str(), "rfc3339" | "unix")
        {
            return Err(error("invalid timestamp format"));
        }
        let input_regex = config::compile_regex(definition.input.pattern.as_deref())?;
        if let Some(regex) = &input_regex {
            let names = regex
                .capture_names()
                .flatten()
                .collect::<std::collections::BTreeSet<_>>();
            if definition
                .mapping
                .values()
                .any(|field| !names.contains(field.as_str()))
            {
                return Err(error("regex mapping refers to an unknown named capture"));
            }
        }
        let detection_regex = config::compile_regex(definition.detect.pattern.as_deref())?;
        let id = format!("parser-declarative-{}", definition.name);
        let version = format!(
            "declarative-v2:sha256={}",
            irmind_app::hex(&irmind_app::sha256(text.as_bytes()))
        );
        let timestamp_context = format!(
            "declared-default-zone={};normalized-utc;source-precision-retained",
            definition.timestamp.default_timezone
        );
        Ok(Self {
            definition,
            id,
            version,
            timestamp_context,
            input_regex,
            detection_regex,
        })
    }

    pub fn description(&self) -> &str {
        &self.definition.description
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn definition_version(&self) -> &str {
        &self.version
    }
}

fn error(message: &'static str) -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::Definition(
        irmind_app::DefinitionError::InvalidFormat(message),
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod completeness_tests;
