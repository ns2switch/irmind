#![forbid(unsafe_code)]
mod decode;
pub use decode::DefenderSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct DefenderParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-defender",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for DefenderParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(DefenderSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for DefenderParser {
    fn parser_name(&self) -> &'static str {
        "parser-defender"
    }
    fn streaming_version(&self) -> &'static str {
        "defender-source-v1"
    }
}
impl LogParser for DefenderParser {
    fn description(&self) -> &'static str {
        "Defender audit exports (experimental)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
