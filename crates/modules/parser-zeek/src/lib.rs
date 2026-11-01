#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::Tainted;
use std::io::{Cursor, Read};

mod mapping;
mod stream;

pub struct ZeekParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-zeek",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};

impl Module for ZeekParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(self)
    }
}

impl LogParser for ZeekParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let sample = &sample[..sample.len().min(64 * 1024)];
        let tsv = sample.starts_with(b"#separator ")
            && sample
                .windows(b"#path\t".len())
                .any(|part| part == b"#path\t")
            && sample
                .windows(b"#fields\t".len())
                .any(|part| part == b"#fields\t");
        if tsv {
            return ParserConfidence::new(95).ok();
        }
        mapping::detect_json(sample).and_then(|score| ParserConfidence::new(score).ok())
    }
}

impl EventParser for ZeekParser {
    fn version(&self) -> &'static str {
        "zeek-log-v1"
    }

    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(AppError::Policy("parser buffer exceeds 50 MiB".into()));
        }
        Ok(self
            .parse_reader_report(source, &mut Cursor::new(bytes), [0; 32], cancel, emit)?
            .accepted)
    }
}

impl StreamingEventParser for ZeekParser {
    fn parser_name(&self) -> &'static str {
        "parser-zeek"
    }

    fn streaming_version(&self) -> &'static str {
        "zeek-log-v1"
    }

    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        evidence_hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Ok(self
            .parse_reader_report(source, reader, evidence_hash, cancel, emit)?
            .accepted)
    }

    fn parse_reader_report(
        &self,
        source: &str,
        reader: &mut dyn Read,
        evidence_hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        stream::parse(source, reader, evidence_hash, cancel, emit)
    }
}

#[cfg(test)]
mod tests;
