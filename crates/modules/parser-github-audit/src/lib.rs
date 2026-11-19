#![forbid(unsafe_code)]
//! Offline GitHub JSON and CSV audit log exports.
mod decode;
pub use decode::GitHubAuditSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

pub struct GitHubAuditParser;

const PARSER: &str = "parser-github-audit";
const VERSION: &str = "github-audit-source-v1";
static MANIFEST: ModuleManifest = ModuleManifest {
    id: PARSER,
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for GitHubAuditParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(GitHubAuditSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl StreamingEventParser for GitHubAuditParser {
    fn parser_name(&self) -> &'static str {
        PARSER
    }

    fn streaming_version(&self) -> &'static str {
        VERSION
    }
}

impl LogParser for GitHubAuditParser {
    fn description(&self) -> &'static str {
        "GitHub audit log JSON and CSV exports (experimental)"
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
