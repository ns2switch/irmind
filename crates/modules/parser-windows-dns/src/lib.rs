#![forbid(unsafe_code)]
//! Offline Windows DNS Server debug packet summaries.
mod decode;
pub use decode::WindowsDnsSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, ParserTimeContext, ParserTimeRequirement,
    StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::SourceDecoderSelection,
};
use std::sync::Arc;

pub struct WindowsDnsParser;

const PARSER: &str = "parser-windows-dns";
const VERSION: &str = "windows-dns-source-v1";
static MANIFEST: ModuleManifest = ModuleManifest {
    id: PARSER,
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for WindowsDnsParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(WindowsDnsSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl StreamingEventParser for WindowsDnsParser {
    fn parser_name(&self) -> &'static str {
        PARSER
    }

    fn streaming_version(&self) -> &'static str {
        VERSION
    }
}

impl LogParser for WindowsDnsParser {
    fn description(&self) -> &'static str {
        "Windows DNS debug packet summaries, M/D/YYYY AM/PM with a confirmed fixed offset (experimental)"
    }

    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(sample).and_then(|(_, score)| ParserConfidence::new(score).ok())
    }

    fn time_context_requirement(
        &self,
        _: &str,
        _: &[u8],
    ) -> Result<Option<ParserTimeRequirement>, AppError> {
        Ok(Some(ParserTimeRequirement {
            required: true,
            hosts: Vec::new(),
            observed: None,
        }))
    }

    fn with_time_context(
        &self,
        context: &ParserTimeContext,
    ) -> Result<Arc<dyn LogParser>, AppError> {
        SourceDecoderSelection::new(Arc::new(WindowsDnsSourceDecoder))
            .with_selector(Arc::new(Self))?
            .with_time_context(context)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
