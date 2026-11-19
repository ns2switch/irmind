#![forbid(unsafe_code)]
//! Bounded decoding of exported Unified Log and Endpoint Security JSON.
mod decode;
pub use decode::MacosSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

pub struct MacosParser;

const PARSER: &str = "parser-macos";
const VERSION: &str = "macos-source-v1";
static MANIFEST: ModuleManifest = ModuleManifest {
    id: PARSER,
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for MacosParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(MacosSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl StreamingEventParser for MacosParser {
    fn parser_name(&self) -> &'static str {
        PARSER
    }

    fn streaming_version(&self) -> &'static str {
        VERSION
    }
}

impl LogParser for MacosParser {
    fn description(&self) -> &'static str {
        "macOS Unified Log and eslogger JSON exports (experimental)"
    }

    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(sample)
            .then(|| ParserConfidence::new(98).ok())
            .flatten()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
