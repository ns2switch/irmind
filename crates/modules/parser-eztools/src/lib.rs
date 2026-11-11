#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::{EztoolsSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, CancellationToken, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use std::io::BufRead;

mod mapping;
pub struct EztoolsParser;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-eztools",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for EztoolsParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(EztoolsSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl LogParser for EztoolsParser {
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        irmind_app::json_time_requirement(
            source,
            sample,
            &irmind_app::ParserTimeFields {
                parser_id: "parser-eztools",
                hosts: &["/columns/Computer"],
                timestamps: &["/columns/TimeCreated"],
            },
        )
    }
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|value| ParserConfidence::new(value).ok())
    }
}

impl StreamingEventParser for EztoolsParser {
    fn parser_name(&self) -> &'static str {
        "parser-eztools"
    }
    fn streaming_version(&self) -> &'static str {
        "eztools-source-v1"
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
            return Err(policy("Eztools CSV source exceeds 50 GiB"));
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

fn csv_record(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut record = Vec::new();
    let mut consumed = 0u64;
    let mut quote_parity = false;
    loop {
        let (line, size, line_odd_quotes) = bounded_line(reader, cancel)?;
        if size == 0 {
            return Ok((record, consumed));
        }
        consumed = consumed.saturating_add(size);
        if consumed > MAX_SOURCE_BYTES {
            return Err(policy("Eztools CSV source exceeds 50 GiB"));
        }
        record.extend_from_slice(
            &line[..line.len().min(
                MAX_RECORD_BYTES
                    .saturating_add(1)
                    .saturating_sub(record.len()),
            )],
        );
        quote_parity ^= line_odd_quotes;
        if !quote_parity {
            return Ok((record, consumed));
        }
    }
}

fn decode_csv(bytes: &[u8]) -> Result<csv::StringRecord, AppError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(bytes);
    let row = reader
        .records()
        .next()
        .ok_or_else(|| policy("empty CSV record"))?
        .map_err(|_| policy("invalid CSV record"))?;
    if reader.records().next().is_some() {
        return Err(policy("unexpected extra CSV record"));
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use irmind_app::CancellationToken;
    const FIXTURE: &[u8] =
        include_bytes!("../../../testkit/fixtures/parser-eztools/source/events.csv");
    #[test]
    fn bad_csv_row_is_rejected_without_losing_next() -> Result<(), AppError> {
        let text = std::str::from_utf8(FIXTURE).map_err(|_| policy("invalid fixture"))?;
        let (header, good) = text
            .split_once('\n')
            .ok_or_else(|| policy("invalid fixture"))?;
        let input = format!("{header}\n,cmd.exe,missing.pf,true\n{good}");
        let report = irmind_testkit::decode_source(
            &EztoolsSourceDecoder,
            "sample.csv",
            &mut input.as_bytes(),
            [3; 32],
            &CancellationToken::new(),
            None,
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (2, 1));
        Ok(())
    }
    #[test]
    fn oversized_multiline_csv_record_does_not_desynchronize_next_row() -> Result<(), AppError> {
        let text = std::str::from_utf8(FIXTURE).map_err(|_| policy("invalid fixture"))?;
        let (header, good) = text
            .split_once('\n')
            .ok_or_else(|| policy("invalid fixture"))?;
        let input = format!(
            "{header}\n\"{}\ncontinued\",cmd.exe,missing.pf,true\n{good}",
            "x".repeat(MAX_RECORD_BYTES)
        );
        let report = irmind_testkit::decode_source(
            &EztoolsSourceDecoder,
            "sample.csv",
            &mut input.as_bytes(),
            [3; 32],
            &CancellationToken::new(),
            None,
            &mut |_| Ok(()),
        )?;
        assert_eq!((report.accepted, report.rejected), (2, 1));
        Ok(())
    }
    #[test]
    fn cancellation_prevents_parsing() {
        let token = CancellationToken::new();
        token.cancel();
        let result = irmind_testkit::decode_source(
            &EztoolsSourceDecoder,
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
            &EztoolsParser,
            &EztoolsSourceDecoder,
            "sample",
            FIXTURE,
            2,
            None,
        )
    }
}
