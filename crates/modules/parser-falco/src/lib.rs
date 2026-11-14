#![forbid(unsafe_code)]
//! Bounded original Falco JSON; rules remain source detections, never confirmed findings.
mod decode;
pub use decode::FalcoSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserClusterRequirement, ParserConfidence, SourceClusterContext,
    StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;
#[derive(Default)]
pub struct FalcoParser {
    context: Option<SourceClusterContext>,
}
pub(crate) const SOURCE_VERSION: &str = "falco-source-v1";
static MODULE: ModuleManifest = ModuleManifest {
    id: "parser-falco",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for FalcoParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(self)?;
        registry.add_source_decoder(Arc::new(FalcoSourceDecoder))
    }
}
impl StreamingEventParser for FalcoParser {
    fn parser_name(&self) -> &'static str {
        "parser-falco"
    }
    fn streaming_version(&self) -> &'static str {
        SOURCE_VERSION
    }
    fn cluster_context(&self) -> Option<&SourceClusterContext> {
        self.context.as_ref()
    }
}
impl LogParser for FalcoParser {
    fn description(&self) -> &'static str {
        "Falco JSON detections (experimental; Kubernetes identities require cluster context)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let fields = sample_fields(sample)?;
        decode::is_falco(&fields)
            .then(|| ParserConfidence::new(98).ok())
            .flatten()
    }
    fn cluster_context_requirement(
        &self,
        _: &str,
        sample: &[u8],
    ) -> Result<Option<ParserClusterRequirement>, AppError> {
        // Later records may require context even if the sample does not. The
        // decoder checks each record again before it can reach publication.
        let required = sample_fields(sample).is_some_and(|fields| decode::is_kubernetes(&fields));
        Ok(Some(ParserClusterRequirement::try_new(required, vec![])?))
    }
    fn with_cluster_context(
        &self,
        context: &SourceClusterContext,
    ) -> Result<Arc<dyn LogParser>, AppError> {
        Ok(Arc::new(Self {
            context: Some(context.clone()),
        }))
    }
}
fn sample_fields(sample: &[u8]) -> Option<irmind_app::source_mapping::SourceValue> {
    let mut input = std::io::Cursor::new(&sample[..sample.len().min(65536)]);
    let cancel = irmind_app::CancellationToken::new();
    let frame = irmind_app::source_mapping::json::JsonFrames::new(&mut input, &cancel)
        .without_record_wrappers()
        .next_frame()
        .ok()??;
    irmind_app::source_mapping::json::decode_json_fields(
        frame.bytes(),
        irmind_app::source_mapping::json::SourceJsonLimits::default(),
    )
    .ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
