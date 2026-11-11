#![forbid(unsafe_code)]
mod source_decode;
pub use source_decode::{SyslogSourceDecoder, source_log_parser};

use irmind_app::{
    AppError, CancellationToken, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};

mod gzip;
mod input;
mod record;
mod time_context;
mod timestamp;
pub use timestamp::LegacyTimestamp;

#[derive(Default)]
pub struct SyslogParser;

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-syslog",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for SyslogParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        config: &ModuleConfig,
    ) -> Result<(), AppError> {
        let _ = config;
        registry.add_source_decoder(std::sync::Arc::new(SyslogSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl LogParser for SyslogParser {
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<irmind_app::ParserTimeRequirement>, AppError> {
        time_context::requirement(self, source, sample)
    }
    fn with_time_context(
        &self,
        context: &irmind_app::ParserTimeContext,
    ) -> Result<std::sync::Arc<dyn LogParser>, AppError> {
        source_log_parser().with_time_context(context)
    }
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let sample = &sample[..sample.len().min(64 * 1024)];
        let expanded;
        let sample = if sample.starts_with(&[0x1f, 0x8b]) {
            expanded = gzip::sample(sample);
            &expanded[..]
        } else {
            sample
        };
        let first = sample.split(|byte| *byte == b'\n').next()?;
        let text = std::str::from_utf8(first).ok()?.trim_end_matches('\r');
        record::detect(text).and_then(|score| ParserConfidence::new(score).ok())
    }
}

impl StreamingEventParser for SyslogParser {
    fn parser_name(&self) -> &'static str {
        "parser-syslog"
    }
    fn streaming_version(&self) -> &'static str {
        "syslog-source-v1"
    }
}

fn invalid() -> AppError {
    AppError::Policy("RFC 3164 requires a valid explicit year and UTC offset".into())
}
fn limit() -> AppError {
    AppError::Policy("syslog source exceeds size or record limits".into())
}

#[cfg(test)]
mod tests;
