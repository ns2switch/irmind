#![forbid(unsafe_code)]
mod digest;
mod gzip;
mod source_decode;
pub use source_decode::JsonSourceDecoder;

use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry, NonEventSource},
};

use std::{borrow::Cow, sync::Arc};

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
    fn description(&self) -> &'static str {
        "CloudTrail, JSON and NDJSON (plain or gzip)"
    }
    fn non_event_source(&self, source: &str, sample: &[u8]) -> Option<NonEventSource> {
        non_event(source, sample)
    }
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        let sample = json_sample(sample);
        irmind_app::json_time_requirement(
            source,
            &sample,
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
        let sample = json_sample(sample);
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

fn json_sample(sample: &[u8]) -> Cow<'_, [u8]> {
    let sample = &sample[..sample.len().min(gzip::SAMPLE_BYTES)];
    if gzip::is_gzip(sample) {
        Cow::Owned(gzip::sample(sample))
    } else {
        Cow::Borrowed(sample)
    }
}

fn non_event(source: &str, sample: &[u8]) -> Option<NonEventSource> {
    let decoded = json_sample(sample);
    let clipped = sample.len() >= gzip::SAMPLE_BYTES || decoded.len() >= gzip::SAMPLE_BYTES;
    digest::detect(source, &decoded, clipped).then_some(NonEventSource::CloudTrailDigest)
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

/// Bind the bounded format checks to the registered original-field decoder.
pub fn source_log_parser() -> std::sync::Arc<dyn irmind_app::LogParser> {
    fn detect(source: &str, sample: &[u8]) -> Option<irmind_app::ParserConfidence> {
        JsonParser.detect(source, sample)
    }
    std::sync::Arc::new(
        irmind_app::source_mapping::SourceDecoderSelection::new(std::sync::Arc::new(
            JsonSourceDecoder,
        ))
        .with_description(crate::JsonParser.description())
        .with_non_event_detector(non_event)
        .with_detector(detect),
    )
}
