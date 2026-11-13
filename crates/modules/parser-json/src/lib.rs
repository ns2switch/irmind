#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::JsonSourceDecoder;

use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};

use std::sync::Arc;

pub struct JsonParser;

impl StreamingEventParser for JsonParser {
    fn parser_name(&self) -> &'static str {
        "parser-json"
    }

    fn streaming_version(&self) -> &'static str {
        "json-source-v1"
    }
}

impl LogParser for JsonParser {
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        irmind_app::json_time_requirement(
            source,
            sample,
            &irmind_app::ParserTimeFields {
                parser_id: "parser-json",
                hosts: &["/host", "/hostname", "/hostName"],
                timestamps: &[
                    "/eventTime",
                    "/timestamp",
                    "/event_time",
                    "/time",
                    "/@timestamp",
                ],
            },
        )
    }
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let first = sample
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())?;
        if !matches!(first, b'{' | b'[') {
            return None;
        }
        let contains = |needle: &[u8]| sample.windows(needle.len()).any(|window| window == needle);
        let known = (contains(b"eventVersion") && contains(b"eventTime"))
            || (contains(b"\"Records\"") && contains(b"eventTime") && contains(b"eventName"))
            || (contains(b"event_id")
                && (contains(b"provider") || (contains(b"account_id") && contains(b"principal"))));
        ParserConfidence::new(if known { 90 } else { 45 }).ok()
    }
}

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-json",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for JsonParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(JsonSourceDecoder))?;
        registry.add_parser(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::wildcard_imports)]
mod tests;

/// Experimental raw decoding preserves the normal detector and historical parser.
pub fn source_log_parser() -> std::sync::Arc<dyn irmind_app::LogParser> {
    fn detect(source: &str, sample: &[u8]) -> Option<irmind_app::ParserConfidence> {
        JsonParser.detect(source, sample)
    }
    std::sync::Arc::new(
        irmind_app::source_mapping::SourceDecoderSelection::new(std::sync::Arc::new(
            JsonSourceDecoder,
        ))
        .with_detector(detect),
    )
}
