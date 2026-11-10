#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::Tainted;
use std::io::{Cursor, Read};

mod mapping;
mod source_decode;
mod stream;
pub use source_decode::{SuricataSourceDecoder, source_log_parser};

pub struct SuricataParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-suricata",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};

impl Module for SuricataParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(SuricataSourceDecoder))?;
        registry.add_parser(self)
    }
}

impl LogParser for SuricataParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        mapping::detect(&sample[..sample.len().min(64 * 1024)])
            .and_then(|score| ParserConfidence::new(score).ok())
    }
}

impl EventParser for SuricataParser {
    fn version(&self) -> &'static str {
        "suricata-eve-v1"
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

impl StreamingEventParser for SuricataParser {
    fn partition_profile(&self, _record: &GraphRecord) -> irmind_app::PartitionProfile {
        irmind_app::PartitionProfile::EndpointHost
    }

    fn source_parallelism(&self, _source: &str) -> Result<irmind_app::SourceParallelism, AppError> {
        Ok(irmind_app::SourceParallelism::Concurrent)
    }

    fn parse_indexed_reader_report(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<irmind_app::IndexedGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.parse_reader_report(source, reader, hash, cancel, &mut |tainted| {
            let mut indexed = None;
            let offset = tainted
                .provenance()
                .parser_location()
                .map(irmind_domain::ParserLocation::byte_offset);
            tainted.inspect(|record| {
                indexed = Some(
                    irmind_app::indexed_rfc3339(&record.at, false, false).map(|time| {
                        irmind_app::IndexedGraphRecord {
                            record: record.clone(),
                            time: Some(time),
                            source_offset: offset,
                        }
                    }),
                );
            });
            let indexed =
                indexed.ok_or_else(|| AppError::Policy("missing network record".into()))??;
            emit(Tainted::from_external(
                indexed,
                tainted.provenance().clone(),
            ))
        })
    }

    fn parser_name(&self) -> &'static str {
        "parser-suricata"
    }

    fn streaming_version(&self) -> &'static str {
        "suricata-eve-v1"
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
