#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::Tainted;
use serde_json::Value;
use std::io::{Cursor, Read, Seek, SeekFrom};

mod json_stream;
mod parquet_input;
mod record;

pub struct OcsfParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-ocsf",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};

impl Module for OcsfParser {
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

impl LogParser for OcsfParser {
    fn detect(&self, source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        if sample.starts_with(b"PAR1") {
            return ParserConfidence::new(if source_name.ends_with(".parquet") {
                55
            } else {
                45
            })
            .ok();
        }
        let first = sample.split(|byte| *byte == b'\n').next()?;
        let value: Value = serde_json::from_slice(&first[..first.len().min(64 * 1024)])
            .or_else(|_| serde_json::from_slice(&sample[..sample.len().min(64 * 1024)]))
            .ok()?;
        let value = value
            .as_array()
            .and_then(|array| array.first())
            .unwrap_or(&value);
        let has_markers = value.get("class_uid").and_then(Value::as_u64).is_some()
            && value.get("category_uid").and_then(Value::as_u64).is_some()
            && value
                .pointer("/metadata/version")
                .and_then(Value::as_str)
                .is_some();
        has_markers
            .then(|| ParserConfidence::new(95).ok())
            .flatten()
    }
}

impl EventParser for OcsfParser {
    fn version(&self) -> &'static str {
        "ocsf-stream-v1"
    }

    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(policy_error("OCSF buffer exceeds 50 MiB"));
        }
        Ok(self
            .parse_reader_report(source, &mut Cursor::new(bytes), [0; 32], cancel, emit)?
            .accepted)
    }
}

impl StreamingEventParser for OcsfParser {
    fn parser_name(&self) -> &'static str {
        "parser-ocsf"
    }

    fn prefers_local_file(&self, _source: &str, sample: &[u8]) -> bool {
        sample.starts_with(b"PAR1")
    }

    fn parse_local_file_report(
        &self,
        source: &str,
        file: &mut std::fs::File,
        evidence_hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        file.seek(SeekFrom::Start(0))
            .map_err(|_| policy_error("cannot seek OCSF source"))?;
        let mut magic = [0; 4];
        file.read_exact(&mut magic)
            .map_err(|_| policy_error("cannot read OCSF source"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| policy_error("cannot seek OCSF source"))?;
        if &magic == b"PAR1" {
            parquet_input::parse(source, file, evidence_hash, cancel, emit)
        } else {
            self.parse_reader_report(source, file, evidence_hash, cancel, emit)
        }
    }

    fn streaming_version(&self) -> &'static str {
        "ocsf-stream-v1"
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
        let mut magic = [0; 4];
        let mut read = 0;
        while read < magic.len() {
            let count = reader
                .read(&mut magic[read..])
                .map_err(|_| policy_error("cannot read OCSF source"))?;
            if count == 0 {
                break;
            }
            read += count;
        }
        let input = Cursor::new(magic[..read].to_vec()).chain(reader);
        if read == magic.len() && &magic == b"PAR1" {
            Err(policy_error(
                "OCSF Parquet requires a seekable local or case-spooled file",
            ))
        } else {
            json_stream::parse(source, input, evidence_hash, cancel, emit)
        }
    }
}

fn policy_error(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}

#[cfg(test)]
mod tests;
