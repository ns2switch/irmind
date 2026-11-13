#![forbid(unsafe_code)]
//! Original Entra export layouts; semantic interpretation is a separate module.
mod decode;
pub use decode::EntraSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
pub struct EntraParser;
static MODULE: ModuleManifest = ModuleManifest {
    id: "parser-entra",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for EntraParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(EntraSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl StreamingEventParser for EntraParser {
    fn parser_name(&self) -> &'static str {
        "parser-entra"
    }
    fn streaming_version(&self) -> &'static str {
        decode::SOURCE_VERSION
    }
}
impl LogParser for EntraParser {
    fn description(&self) -> &'static str {
        "Microsoft Entra sign-in and directory audit exports (experimental)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let mut reader = std::io::Cursor::new(&sample[..sample.len().min(65536)]);
        let cancel = irmind_app::CancellationToken::new();
        let mut frames = irmind_app::source_mapping::json::JsonFrames::new(&mut reader, &cancel);
        let first = frames.next_frame().ok()??;
        let fields = irmind_app::source_mapping::json::decode_json_fields(
            first.bytes(),
            irmind_app::source_mapping::json::SourceJsonLimits::default(),
        )
        .ok()?;
        let (_, keys) = decode::layout(&fields)?;
        decode::timestamp(&fields, keys).ok()?;
        ParserConfidence::new(98).ok()
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
