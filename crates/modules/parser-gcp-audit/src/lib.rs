#![forbid(unsafe_code)]
//! Original Cloud Audit `LogEntry` fields. Interpretation stays in mappings.
mod decode;
pub use decode::GcpAuditSourceDecoder;
use irmind_app::{
    AppError, LogParser, ParserClusterRequirement, ParserConfidence, SourceClusterContext,
    StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::sync::Arc;

#[derive(Default)]
pub struct GcpAuditParser {
    context: Option<SourceClusterContext>,
}
pub(crate) const SOURCE_VERSION: &str = "gcp-audit-source-v1";
static MODULE: ModuleManifest = ModuleManifest {
    id: "parser-gcp-audit",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for GcpAuditParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(self)?;
        registry.add_source_decoder(Arc::new(GcpAuditSourceDecoder))
    }
}
impl StreamingEventParser for GcpAuditParser {
    fn parser_name(&self) -> &'static str {
        "parser-gcp-audit"
    }
    fn streaming_version(&self) -> &'static str {
        SOURCE_VERSION
    }
    fn cluster_context(&self) -> Option<&SourceClusterContext> {
        self.context.as_ref()
    }
}
impl LogParser for GcpAuditParser {
    fn description(&self) -> &'static str {
        "GCP Cloud Audit Logs (experimental; GKE identities require cluster confirmation)"
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let fields = sample_fields(sample)?;
        decode::is_audit(&fields)
            .then(|| ParserConfidence::new(98).ok())
            .flatten()
    }
    fn cluster_context_requirement(
        &self,
        _: &str,
        sample: &[u8],
    ) -> Result<Option<ParserClusterRequirement>, AppError> {
        let mut input = std::io::Cursor::new(&sample[..sample.len().min(65536)]);
        let cancel = irmind_app::CancellationToken::new();
        let mut frames = irmind_app::source_mapping::json::JsonFrames::new(&mut input, &cancel)
            .without_record_wrappers();
        let mut required = false;
        let mut claims = Vec::new();
        while let Ok(Some(frame)) = frames.next_frame() {
            let Ok(fields) = irmind_app::source_mapping::json::decode_json_fields(
                frame.bytes(),
                irmind_app::source_mapping::json::SourceJsonLimits::default(),
            ) else {
                continue;
            };
            if !decode::is_gke(&fields) {
                continue;
            }
            required = true;
            if let Ok(Some(claim)) = decode::gke_claim(&fields)
                && !claims.contains(&claim)
            {
                claims.push(claim);
                if claims.len() > irmind_domain::MAX_SOURCE_CLUSTERS {
                    return Err(AppError::Policy("An export may bind at most eight confirmed clusters; split this export by cluster".into()));
                }
            }
        }
        if !required {
            return Ok(None);
        }
        claims.sort();
        Ok(Some(ParserClusterRequirement::try_new(true, claims)?))
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
    let sample = &sample[..sample.len().min(65536)];
    let mut input = std::io::Cursor::new(sample);
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
