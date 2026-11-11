#![forbid(unsafe_code)]

use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};

mod mapping;
mod source_decode;
pub use source_decode::{SuricataSourceDecoder, source_log_parser};

pub struct SuricataParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-suricata",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for SuricataParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(SuricataSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl LogParser for SuricataParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|score| ParserConfidence::new(score).ok())
    }
}

impl StreamingEventParser for SuricataParser {
    fn source_parallelism(&self, _source: &str) -> Result<irmind_app::SourceParallelism, AppError> {
        Ok(irmind_app::SourceParallelism::Concurrent)
    }

    fn parser_name(&self) -> &'static str {
        "parser-suricata"
    }

    fn streaming_version(&self) -> &'static str {
        "suricata-source-v1"
    }
}

#[cfg(test)]
mod tests;
