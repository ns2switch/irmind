#![forbid(unsafe_code)]

use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};

mod mapping;
mod source_decode;
mod stream;
pub use source_decode::{ZeekSourceDecoder, source_log_parser};

pub struct ZeekParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-zeek",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for ZeekParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(ZeekSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl LogParser for ZeekParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let sample = &sample[..sample.len().min(64 * 1024)];
        let tsv = sample.starts_with(b"#separator ")
            && sample
                .windows(b"#path\t".len())
                .any(|part| part == b"#path\t")
            && sample
                .windows(b"#fields\t".len())
                .any(|part| part == b"#fields\t");
        if tsv {
            return ParserConfidence::new(95).ok();
        }
        mapping::detect_json(sample).and_then(|score| ParserConfidence::new(score).ok())
    }
}

impl StreamingEventParser for ZeekParser {
    fn source_parallelism(&self, _source: &str) -> Result<irmind_app::SourceParallelism, AppError> {
        Ok(irmind_app::SourceParallelism::Concurrent)
    }

    fn parser_name(&self) -> &'static str {
        "parser-zeek"
    }

    fn streaming_version(&self) -> &'static str {
        "zeek-source-v1"
    }
}

#[cfg(test)]
mod tests;
