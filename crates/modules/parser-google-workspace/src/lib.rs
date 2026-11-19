#![forbid(unsafe_code)]
//! Offline Google Workspace Reports API activity pages and individual activities.
mod decode;
pub use decode::GoogleWorkspaceSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

pub struct GoogleWorkspaceParser;

const PARSER: &str = "parser-google-workspace";
const VERSION: &str = "google-workspace-source-v1";
static MANIFEST: ModuleManifest = ModuleManifest {
    id: PARSER,
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for GoogleWorkspaceParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(GoogleWorkspaceSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl StreamingEventParser for GoogleWorkspaceParser {
    fn parser_name(&self) -> &'static str {
        PARSER
    }

    fn streaming_version(&self) -> &'static str {
        VERSION
    }
}

impl LogParser for GoogleWorkspaceParser {
    fn description(&self) -> &'static str {
        "Google Workspace Reports API JSON exports (experimental)"
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
