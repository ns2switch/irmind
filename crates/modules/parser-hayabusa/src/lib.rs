#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::{HayabusaSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, CancellationToken, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::io::BufRead;

mod csv;
mod mapping;
pub struct HayabusaParser;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-hayabusa",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for HayabusaParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(HayabusaSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl LogParser for HayabusaParser {
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        irmind_app::json_time_requirement(
            source,
            sample,
            &irmind_app::ParserTimeFields {
                parser_id: "parser-hayabusa",
                hosts: &["/Computer"],
                timestamps: &["/Timestamp"],
            },
        )
    }
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|value| ParserConfidence::new(value).ok())
    }
}

impl StreamingEventParser for HayabusaParser {
    fn parser_name(&self) -> &'static str {
        "parser-hayabusa"
    }
    fn streaming_version(&self) -> &'static str {
        "hayabusa-source-v1"
    }
}
fn bounded_line(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64, bool), AppError> {
    let mut line = Vec::new();
    let mut consumed = 0u64;
    let mut odd_quotes = false;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let available = reader
            .fill_buf()
            .map_err(|_| policy("cannot read parser source"))?;
        if available.is_empty() {
            return Ok((line, consumed, odd_quotes));
        }
        let end = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |p| p + 1);
        let newline = available[end - 1] == b'\n';
        odd_quotes ^= available[..end]
            .iter()
            .fold(false, |odd, byte| odd ^ (*byte == b'"'));
        let room = MAX_RECORD_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        line.extend_from_slice(&available[..end.min(room)]);
        consumed = consumed.saturating_add(end as u64);
        if consumed > MAX_SOURCE_BYTES {
            return Err(policy("Hayabusa source exceeds 50 GiB"));
        }
        reader.consume(end);
        if newline {
            return Ok((line, consumed, odd_quotes));
        }
    }
}

fn policy(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::CancellationToken;
    const FIXTURE: &[u8] =
        include_bytes!("../../../testkit/fixtures/parser-hayabusa/source/events.jsonl");
    #[test]
    fn csv_timeline_is_parsed_with_explicit_offset() -> Result<(), AppError> {
        let input=b"Timestamp,RuleTitle,Level,Computer,Channel,Details\n2026-10-23 13:03:00.000 +01:00,Synthetic task,high,lab-host,Security,TaskName=DemoTask\n";
        assert!(HayabusaParser.detect("timeline.csv", input).is_some());
        let mut records = Vec::new();
        let report = irmind_testkit::decode_source(
            &HayabusaSourceDecoder,
            "timeline.csv",
            &mut input.as_ref(),
            [3; 32],
            &CancellationToken::new(),
            None,
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )?;
        assert_eq!((report.accepted, report.rejected), (1, 0));
        records[0].inspect(|record| {
            assert_eq!(
                record.timestamp().unwrap().to_rfc3339(),
                "2026-10-23T12:03:00.000Z"
            );
        });
        Ok(())
    }
    #[test]
    fn bad_record_is_rejected_without_losing_next() -> Result<(), AppError> {
        let mut input = b"{broken}\n".to_vec();
        input.extend_from_slice(FIXTURE);
        let report = irmind_testkit::decode_source(
            &HayabusaSourceDecoder,
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
    fn oversized_multiline_csv_record_does_not_desynchronize_next_row() -> Result<(), AppError> {
        let input = format!(
            "Timestamp,RuleTitle,Computer\n2026-10-23T12:00:00Z,\"{}\ncontinued\",host\n2026-10-23T12:01:00Z,Valid,host\n",
            "x".repeat(MAX_RECORD_BYTES)
        );
        let report = irmind_testkit::decode_source(
            &HayabusaSourceDecoder,
            "timeline.csv",
            &mut input.as_bytes(),
            [3; 32],
            &CancellationToken::new(),
            None,
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (1, 1));
        Ok(())
    }
    #[test]
    fn cancellation_prevents_parsing() {
        let token = CancellationToken::new();
        token.cancel();
        let result = irmind_testkit::decode_source(
            &HayabusaSourceDecoder,
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
            &HayabusaParser,
            &HayabusaSourceDecoder,
            "sample",
            FIXTURE,
            2,
            None,
        )
    }
}

#[cfg(test)]
mod completeness_tests;
