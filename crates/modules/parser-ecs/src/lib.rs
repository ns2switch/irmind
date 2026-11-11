#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::{EcsSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, CancellationToken, LogParser, ParseReport, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use serde_json::Value;
use std::io::BufRead;

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;

pub struct EcsParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-ecs",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for EcsParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(self)?;
        registry.add_source_decoder(std::sync::Arc::new(EcsSourceDecoder))
    }
}

impl LogParser for EcsParser {
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        irmind_app::json_time_requirement(
            source,
            sample,
            &irmind_app::ParserTimeFields {
                parser_id: "parser-ecs",
                hosts: &["/host/name", "/host.name"],
                timestamps: &["/@timestamp"],
            },
        )
    }
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let first = sample.split(|byte| *byte == b'\n').next()?;
        let value: Value = serde_json::from_slice(&first[..first.len().min(64 * 1024)]).ok()?;
        let confidence =
            if field(&value, "/@timestamp").is_some() && field(&value, "/ecs/version").is_some() {
                95
            } else if field(&value, "/@timestamp").is_some()
                && field(&value, "/event/kind").is_some()
                && field(&value, "/host/name").is_some()
            {
                85
            } else {
                return None;
            };
        ParserConfidence::new(confidence).ok()
    }
}

impl StreamingEventParser for EcsParser {
    fn parser_name(&self) -> &'static str {
        "parser-ecs"
    }

    fn streaming_version(&self) -> &'static str {
        "ecs-source-v1"
    }
}

fn bounded_line(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
    remaining: u64,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut line = Vec::new();
    let mut consumed = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let available = reader
            .fill_buf()
            .map_err(|_| policy_error("cannot read ECS source"))?;
        if available.is_empty() {
            return Ok((line, consumed));
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        let newline = available[end - 1] == b'\n';
        let room = MAX_RECORD_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        line.extend_from_slice(&available[..end.min(room)]);
        consumed = consumed.saturating_add(end as u64);
        if consumed > remaining {
            return Err(policy_error("parser source exceeds 50 GiB"));
        }
        reader.consume(end);
        if newline {
            return Ok((line, consumed));
        }
    }
}

fn reject(report: &mut ParseReport, line: &[u8]) {
    report.rejected += 1;
    if report.samples.len() < 3 {
        report.samples.push(
            String::from_utf8_lossy(&line[..line.len().min(256)])
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
}

fn field<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    value.pointer(path).and_then(Value::as_str)
}

fn policy_error(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

#[cfg(test)]
mod completeness_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod source_tests;
