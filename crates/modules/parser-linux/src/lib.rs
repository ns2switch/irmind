#![forbid(unsafe_code)]
mod indexed;
mod source_decode;
pub use source_decode::JournalSourceDecoder;

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, ParserIdentity, ParserTimeContext, ParserTimeRequirement,
    StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::Tainted;
use std::{
    io::{Cursor, Read},
    sync::Arc,
};

mod audit;
mod auth;
mod bounds;
mod input;
mod journal;
mod record;
mod time;
mod version;
pub use version::HistoricalResolver;
mod web;

#[derive(Default)]
pub struct LinuxParser {
    context: Option<ParserTimeContext>,
    version: Option<String>,
    timestamp_context: Option<String>,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-linux",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
impl Module for LinuxParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new(JournalSourceDecoder))?;
        registry.add_parser(self)
    }
}
impl LogParser for LinuxParser {
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let line = sample[..sample.len().min(65_536)]
            .split(|byte| *byte == b'\n')
            .next()?;
        let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        let recognized =
            auth::detect(line) || audit::detect(line) || journal::detect(line) || web::detect(line);
        recognized.then(|| ParserConfidence::new(95).ok()).flatten()
    }
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<ParserTimeRequirement>, AppError> {
        time::requirement(self, source, sample)
    }
    fn with_time_context(
        &self,
        context: &ParserTimeContext,
    ) -> Result<Arc<dyn LogParser>, AppError> {
        Ok(Arc::new(Self::configured(*context)))
    }
}
impl EventParser for LinuxParser {
    fn version(&self) -> &'static str {
        "linux-v1"
    }
    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(bad("Linux parser buffer exceeds 50 MiB"));
        }
        self.parse_reader(
            source,
            &mut Cursor::new(bytes),
            irmind_app::sha256(bytes),
            cancel,
            emit,
        )
    }
}
impl StreamingEventParser for LinuxParser {
    fn partition_profile(&self, _record: &GraphRecord) -> irmind_app::PartitionProfile {
        irmind_app::PartitionProfile::EndpointHost
    }

    fn parser_name(&self) -> &'static str {
        "parser-linux"
    }
    fn streaming_version(&self) -> &'static str {
        "linux-v1"
    }
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: self.parser_name(),
            version: self.version.as_deref().unwrap_or("linux-v1"),
        }
    }
    fn identity_for_source(&self, _source: &str) -> Result<ParserIdentity<'_>, AppError> {
        Ok(self.identity())
    }
    fn timestamp_context(&self) -> Option<&str> {
        self.timestamp_context.as_deref()
    }
    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Ok(self
            .parse_reader_report(source, reader, hash, cancel, emit)?
            .accepted)
    }
    fn parse_reader_report(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        input::parse(self, source, reader, hash, cancel, emit)
    }

    fn parse_indexed_reader_report(
        &self,
        source: &str,
        reader: &mut dyn std::io::Read,
        evidence_hash: [u8; 32],
        cancel: &irmind_app::CancellationToken,
        emit: &mut dyn FnMut(
            irmind_domain::Tainted<irmind_app::IndexedGraphRecord>,
        ) -> Result<(), irmind_app::AppError>,
    ) -> Result<irmind_app::ParseReport, irmind_app::AppError> {
        irmind_app::parse_indexed_report(
            |forward| self.parse_reader_report(source, reader, evidence_hash, cancel, forward),
            crate::indexed::project,
            emit,
        )
    }
}
fn bad(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod completeness_tests;

/// Experimental raw decoding preserves the normal detector and historical parser.
pub fn source_log_parser() -> std::sync::Arc<dyn irmind_app::LogParser> {
    fn detect(source: &str, sample: &[u8]) -> Option<irmind_app::ParserConfidence> {
        let _ = source;
        std::str::from_utf8(sample.split(|b| *b == b'\n').next()?)
            .ok()
            .filter(|line| journal::detect(line))
            .and_then(|_| ParserConfidence::new(95).ok())
    }
    std::sync::Arc::new(
        irmind_app::source_mapping::SourceDecoderSelection::new(std::sync::Arc::new(
            JournalSourceDecoder,
        ))
        .with_detector(detect),
    )
}
