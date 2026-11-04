use crate::{AppError, DeclarativeParser, error};
use irmind_app::{
    CancellationToken, EventParser, GraphRecord, LogParser, ParseReport, ParserConfidence,
    ParserIdentity, StreamingEventParser,
};
use irmind_domain::Tainted;
use std::io::{Cursor, Read};

impl EventParser for DeclarativeParser {
    fn version(&self) -> &'static str {
        "declarative-v2"
    }
    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(error("declarative buffered input exceeds 50 MiB"));
        }
        Ok(self
            .parse_source(
                source,
                &mut Cursor::new(bytes),
                irmind_app::sha256(bytes),
                cancel,
                emit,
            )?
            .accepted)
    }
}

impl StreamingEventParser for DeclarativeParser {
    fn partition_profile(&self, _record: &GraphRecord) -> irmind_app::PartitionProfile {
        if self.definition.mapping.contains_key("host") {
            irmind_app::PartitionProfile::EndpointHost
        } else {
            irmind_app::PartitionProfile::Unpartitioned
        }
    }

    fn parser_name(&self) -> &'static str {
        "parser-declarative"
    }
    fn streaming_version(&self) -> &'static str {
        "declarative-v2"
    }
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: self.id(),
            version: self.definition_version(),
        }
    }
    fn identity_for_source(&self, _: &str) -> Result<ParserIdentity<'_>, AppError> {
        Ok(self.identity())
    }
    fn timestamp_context(&self) -> Option<&str> {
        Some(&self.timestamp_context)
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
            .parse_source(source, reader, hash, cancel, emit)?
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
        self.parse_source(source, reader, hash, cancel, emit)
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
            |record| crate::indexed::project(self, record),
            emit,
        )
    }
}

impl LogParser for DeclarativeParser {
    fn description(&self) -> &str {
        self.description()
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        self.detect_sample(sample)
    }
}
