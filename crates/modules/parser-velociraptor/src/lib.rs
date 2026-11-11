#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::{VelociraptorSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};

mod mapping;
pub struct VelociraptorParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-velociraptor",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for VelociraptorParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(VelociraptorSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl LogParser for VelociraptorParser {
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        irmind_app::json_time_requirement(
            source,
            sample,
            &irmind_app::ParserTimeFields {
                parser_id: "parser-velociraptor",
                hosts: &["/Host", "/Hostname"],
                timestamps: &["/Timestamp", "/Time", "/timestamp"],
            },
        )
    }
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|value| ParserConfidence::new(value).ok())
    }
}

impl StreamingEventParser for VelociraptorParser {
    fn parser_name(&self) -> &'static str {
        "parser-velociraptor"
    }
    fn streaming_version(&self) -> &'static str {
        "velociraptor-source-v1"
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use irmind_app::CancellationToken;
    const FIXTURE: &[u8] =
        include_bytes!("../../../testkit/fixtures/parser-velociraptor/source/events.jsonl");
    #[test]
    fn bad_record_is_rejected_without_losing_next() -> Result<(), AppError> {
        let mut input = b"{broken}\n".to_vec();
        input.extend_from_slice(FIXTURE);
        let report = irmind_testkit::decode_source(
            &VelociraptorSourceDecoder,
            "sample.jsonl",
            &mut input.as_slice(),
            [3; 32],
            &CancellationToken::new(),
            None,
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (2, 1));
        assert!(!report.samples.is_empty());
        Ok(())
    }
    #[test]
    fn cancellation_prevents_parsing() {
        let token = CancellationToken::new();
        token.cancel();
        let result = irmind_testkit::decode_source(
            &VelociraptorSourceDecoder,
            "sample",
            &mut &FIXTURE[..],
            [3; 32],
            &token,
            None,
            &mut |_| Ok(()),
        );
        assert!(matches!(result, Err(AppError::Cancelled)));
    }
    #[test]
    fn synthetic_episode_passes_the_original_source_contract() -> Result<(), AppError> {
        irmind_testkit::run_log_parser_contract(
            &VelociraptorParser,
            &VelociraptorSourceDecoder,
            "sample",
            FIXTURE,
            2,
            None,
        )
    }
}

#[cfg(test)]
mod completeness_tests;
