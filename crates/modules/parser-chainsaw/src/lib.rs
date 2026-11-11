#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::{ChainsawSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};

mod mapping;
pub struct ChainsawParser;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-chainsaw",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for ChainsawParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(ChainsawSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl LogParser for ChainsawParser {
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        irmind_app::json_time_requirement(
            source,
            sample,
            &irmind_app::ParserTimeFields {
                parser_id: "parser-chainsaw",
                hosts: &["/computer", "/Computer"],
                timestamps: &["/timestamp", "/Timestamp"],
            },
        )
    }
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|value| ParserConfidence::new(value).ok())
    }
}

impl StreamingEventParser for ChainsawParser {
    fn parser_name(&self) -> &'static str {
        "parser-chainsaw"
    }
    fn streaming_version(&self) -> &'static str {
        "chainsaw-source-v1"
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn policy(message: &'static str) -> AppError {
        AppError::Policy(message.into())
    }
    use irmind_app::CancellationToken;
    const FIXTURE: &[u8] =
        include_bytes!("../../../testkit/fixtures/parser-chainsaw/source/events.jsonl");
    #[test]
    fn parses_upstream_shaped_hunt_output() -> Result<(), AppError> {
        let input=br#"[{"group":"Synthetic service","kind":"individual","document":{"kind":"evtx","data":{"Event":{"System":{"Computer":"lab-host","EventID":7045,"TimeCreated":{"SystemTime":"2026-10-23T12:01:00Z"}},"EventData":{"SubjectUserName":"analyst","NewProcessName":"C:/Synthetic/service.exe"}}}}}]"#;
        assert!(ChainsawParser.detect("hunt.json", input).is_some());
        let mut records = Vec::new();
        let report = irmind_testkit::decode_source(
            &ChainsawSourceDecoder,
            "hunt.json",
            &mut input.as_ref(),
            [5; 32],
            &CancellationToken::new(),
            None,
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )?;
        assert_eq!((report.accepted, report.rejected), (1, 0));
        records[0].inspect(|record| {
            let id = record
                .fields()
                .field("document")
                .unwrap()
                .field("data")
                .unwrap()
                .field("Event")
                .unwrap()
                .field("System")
                .unwrap()
                .field("EventID")
                .unwrap();
            assert!(
                matches!(id, irmind_domain::SourceValue::Number(value) if value.as_str()=="7045")
            );
        });
        Ok(())
    }
    #[test]
    fn parses_json_array_without_loading_entire_source() -> Result<(), AppError> {
        let objects = std::str::from_utf8(FIXTURE).map_err(|_| policy("invalid fixture"))?;
        let input = format!("[{}]", objects.lines().collect::<Vec<_>>().join(","));
        let mut count = 0;
        let report = irmind_testkit::decode_source(
            &ChainsawSourceDecoder,
            "hunt.json",
            &mut input.as_bytes(),
            [4; 32],
            &CancellationToken::new(),
            None,
            &mut |_| {
                count += 1;
                Ok(())
            },
        )?;
        assert_eq!((report.accepted, report.rejected, count), (2, 0, 2));
        assert!(
            ChainsawParser
                .detect("hunt.json", input.as_bytes())
                .is_some()
        );
        Ok(())
    }
    #[test]
    fn bad_record_is_rejected_without_losing_next() -> Result<(), AppError> {
        let mut input = b"{broken}\n".to_vec();
        input.extend_from_slice(FIXTURE);
        let report = irmind_testkit::decode_source(
            &ChainsawSourceDecoder,
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
            &ChainsawSourceDecoder,
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
            &ChainsawParser,
            &ChainsawSourceDecoder,
            "sample",
            FIXTURE,
            2,
            None,
        )
    }
}

#[cfg(test)]
mod completeness_tests;
