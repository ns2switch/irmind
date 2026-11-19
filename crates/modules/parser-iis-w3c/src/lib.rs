#![forbid(unsafe_code)]
//! Offline IIS W3C extended web logs.
mod decode;
pub use decode::IisW3cSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

pub struct IisW3cParser;

const PARSER: &str = "parser-iis-w3c";
const VERSION: &str = "iis-w3c-source-v1";
static MANIFEST: ModuleManifest = ModuleManifest {
    id: PARSER,
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for IisW3cParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(IisW3cSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl StreamingEventParser for IisW3cParser {
    fn parser_name(&self) -> &'static str {
        PARSER
    }

    fn streaming_version(&self) -> &'static str {
        VERSION
    }
}

impl LogParser for IisW3cParser {
    fn description(&self) -> &'static str {
        "IIS W3C extended web logs (experimental)"
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
