#![forbid(unsafe_code)]
mod decode;
mod gzip;
pub use decode::FdrSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct FdrParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-fdr",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for FdrParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(FdrSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for FdrParser {
    fn parser_name(&self) -> &'static str {
        "parser-fdr"
    }
    fn streaming_version(&self) -> &'static str {
        "fdr-source-v1"
    }
}
impl LogParser for FdrParser {
    fn description(&self) -> &'static str {
        "Falcon Data Replicator JSONL and gzip (experimental)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
