#![forbid(unsafe_code)]
mod source_frames;
pub use source_frames::{LinuxSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, CancellationToken, LogParser, ParserConfidence, ParserTimeContext,
    ParserTimeRequirement, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

mod audit;
mod auth;
mod bounds;
mod journal;
mod time;
mod web;

#[derive(Default)]
pub struct LinuxParser;

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-linux",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for LinuxParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(LinuxSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl LogParser for LinuxParser {
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let line = sample[..sample.len().min(65_536)]
            .split(|byte| *byte == b'\n')
            .next()?;
        let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        let recognized =
            auth::detect(line) || audit::detect(line) || journal::detect(line) || web::detect(line);
        recognized.then(|| ParserConfidence::new(95).ok()).flatten()
    }
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<ParserTimeRequirement>, AppError> {
        time::requirement(self, source, sample)
    }
    fn with_time_context(
        &self,
        context: &ParserTimeContext,
    ) -> Result<Arc<dyn LogParser>, AppError> {
        source_log_parser().with_time_context(context)
    }
}

impl StreamingEventParser for LinuxParser {
    fn parser_name(&self) -> &'static str {
        "parser-linux"
    }
    fn streaming_version(&self) -> &'static str {
        "linux-source-v1"
    }
}
fn bad(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod completeness_tests;
