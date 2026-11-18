#![forbid(unsafe_code)]
mod decode;
pub use decode::M365SourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct M365Parser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-m365",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for M365Parser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(M365SourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for M365Parser {
    fn parser_name(&self) -> &'static str {
        "parser-m365"
    }
    fn streaming_version(&self) -> &'static str {
        "m365-source-v1"
    }
}
impl LogParser for M365Parser {
    fn description(&self) -> &'static str {
        "M365 audit exports (experimental)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
