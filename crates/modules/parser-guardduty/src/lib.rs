#![forbid(unsafe_code)]
mod decode;
pub use decode::GuardDutySourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct GuardDutyParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-guardduty",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for GuardDutyParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(GuardDutySourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for GuardDutyParser {
    fn parser_name(&self) -> &'static str {
        "parser-guardduty"
    }
    fn streaming_version(&self) -> &'static str {
        "guardduty-source-v1"
    }
}
impl LogParser for GuardDutyParser {
    fn description(&self) -> &'static str {
        "GuardDuty audit exports (experimental)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
