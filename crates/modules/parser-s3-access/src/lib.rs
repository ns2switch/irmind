#![forbid(unsafe_code)]
//! Offline S3 server access logs.
mod decode;
pub use decode::S3AccessSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

pub struct S3AccessParser;

const PARSER: &str = "parser-s3-access";
const VERSION: &str = "s3-access-source-v1";
static MANIFEST: ModuleManifest = ModuleManifest {
    id: PARSER,
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for S3AccessParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(S3AccessSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl StreamingEventParser for S3AccessParser {
    fn parser_name(&self) -> &'static str {
        PARSER
    }

    fn streaming_version(&self) -> &'static str {
        VERSION
    }
}

impl LogParser for S3AccessParser {
    fn description(&self) -> &'static str {
        "Amazon S3 server access logs (experimental)"
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
