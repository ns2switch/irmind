#![forbid(unsafe_code)]
mod body;
mod decode;
mod headers;
mod mime;
mod urls;
pub use decode::EmailSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct EmailParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-email",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for EmailParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(EmailSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for EmailParser {
    fn parser_name(&self) -> &'static str {
        "parser-email"
    }
    fn streaming_version(&self) -> &'static str {
        "email-source-v1"
    }
}
impl LogParser for EmailParser {
    fn description(&self) -> &'static str {
        "RFC 5322 email exports (experimental); headers, text and MIME metadata only; HTML is never rendered."
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        headers::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
fn limit() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceLimit)
}
fn number(value: usize) -> Result<irmind_app::source_mapping::SourceValue, AppError> {
    Ok(irmind_app::source_mapping::SourceValue::Number(
        irmind_app::source_mapping::SourceNumber::try_new(&value.to_string())
            .map_err(|_| limit())?,
    ))
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
