#![forbid(unsafe_code)]
mod decode;
mod gzip;
mod normalization;
pub use decode::VpcFlowSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct VpcFlowParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-vpc-flow",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for VpcFlowParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(VpcFlowSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for VpcFlowParser {
    fn parser_name(&self) -> &'static str {
        "parser-vpc-flow"
    }
    fn streaming_version(&self) -> &'static str {
        "vpc-flow-source-v1"
    }
}
impl LogParser for VpcFlowParser {
    fn description(&self) -> &'static str {
        "AWS VPC Flow Logs (experimental). Without a header, confirm the standard 14-field version 2 layout before ingestion."
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        decode::detect(&sample[..sample.len().min(65536)])
            .and_then(|n| ParserConfidence::new(n).ok())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
