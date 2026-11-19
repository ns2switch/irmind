#![forbid(unsafe_code)]
mod decode;
pub use decode::GcpFlowSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct GcpFlowParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-gcp-flow",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for GcpFlowParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(GcpFlowSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for GcpFlowParser {
    fn parser_name(&self) -> &'static str {
        "parser-gcp-flow"
    }
    fn streaming_version(&self) -> &'static str {
        "gcp-flow-source-v1"
    }
}
impl LogParser for GcpFlowParser {
    fn description(&self) -> &'static str {
        "GCP VPC Flow Logs exports (experimental)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
