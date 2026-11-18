#![forbid(unsafe_code)]
mod decode;
pub use decode::OktaSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct OktaParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-okta",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for OktaParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(OktaSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for OktaParser {
    fn parser_name(&self) -> &'static str {
        "parser-okta"
    }
    fn streaming_version(&self) -> &'static str {
        "okta-source-v1"
    }
}
impl LogParser for OktaParser {
    fn description(&self) -> &'static str {
        "Okta audit exports (experimental)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
