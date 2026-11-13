#![forbid(unsafe_code)]
//! Original Kubernetes audit fields. Semantic classification belongs to mappings.
mod decode;
mod managed;
pub use decode::KubernetesSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserClusterRequirement, ParserConfidence, SourceClusterContext,
    StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

#[derive(Default)]
pub struct KubernetesParser {
    context: Option<SourceClusterContext>,
}
pub(crate) const SOURCE_VERSION: &str = "kubernetes-source-v1";
static MODULE: ModuleManifest = ModuleManifest {
    id: "parser-kubernetes",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for KubernetesParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(self)?;
        registry.add_source_decoder(Arc::new(KubernetesSourceDecoder))
    }
}
impl StreamingEventParser for KubernetesParser {
    fn parser_name(&self) -> &'static str {
        "parser-kubernetes"
    }
    fn streaming_version(&self) -> &'static str {
        SOURCE_VERSION
    }
    fn cluster_context(&self) -> Option<&SourceClusterContext> {
        self.context.as_ref()
    }
}
impl LogParser for KubernetesParser {
    fn description(&self) -> &'static str {
        "Kubernetes audit events (experimental; explicit cluster identity required)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        managed::detect(sample).and_then(|()| ParserConfidence::new(98).ok())
    }

    fn cluster_context_requirement(
        &self,
        _: &str,
        sample: &[u8],
    ) -> Result<Option<ParserClusterRequirement>, AppError> {
        managed::requirement(sample).map(Some)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod managed_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
