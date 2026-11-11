#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::{OcsfSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use serde_json::Value;

mod json_stream;
mod parquet_input;

pub struct OcsfParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-ocsf",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for OcsfParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(OcsfSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl LogParser for OcsfParser {
    fn detect(&self, source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        if sample.starts_with(b"PAR1") {
            return ParserConfidence::new(if source_name.ends_with(".parquet") {
                55
            } else {
                45
            })
            .ok();
        }
        let first = sample.split(|byte| *byte == b'\n').next()?;
        let value: Value = serde_json::from_slice(&first[..first.len().min(64 * 1024)])
            .or_else(|_| serde_json::from_slice(&sample[..sample.len().min(64 * 1024)]))
            .ok()?;
        let value = value
            .as_array()
            .and_then(|array| array.first())
            .unwrap_or(&value);
        let has_markers = value.get("class_uid").and_then(Value::as_u64).is_some()
            && value.get("category_uid").and_then(Value::as_u64).is_some()
            && value
                .pointer("/metadata/version")
                .and_then(Value::as_str)
                .is_some();
        has_markers
            .then(|| ParserConfidence::new(95).ok())
            .flatten()
    }
}

impl StreamingEventParser for OcsfParser {
    fn parser_name(&self) -> &'static str {
        "parser-ocsf"
    }

    fn prefers_local_file(&self, _source: &str, sample: &[u8]) -> bool {
        sample.starts_with(b"PAR1")
    }

    fn streaming_version(&self) -> &'static str {
        "ocsf-source-v1"
    }
}

fn policy_error(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod completeness_tests;
