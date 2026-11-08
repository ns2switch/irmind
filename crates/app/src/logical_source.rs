//! Bind parser semantics and provenance to the logical source, not its spool.
use crate::{
    AppError, CancellationToken, GraphRecord, IndexedGraphRecord, ParseReport, ParserIdentity,
    PartitionProfile, StreamingEventParser,
};
use irmind_domain::Tainted;
use std::{fs::File, io::Read};

pub struct SourceParser<'a> {
    inner: &'a dyn StreamingEventParser,
    logical: &'a str,
}
impl<'a> SourceParser<'a> {
    pub const fn new(inner: &'a dyn StreamingEventParser, logical: &'a str) -> Self {
        Self { inner, logical }
    }
}
impl StreamingEventParser for SourceParser<'_> {
    fn logical_source<'a>(&'a self, _: &'a str) -> &'a str {
        self.inner.logical_source(self.logical)
    }
    fn parse_common_reader_report(
        &self,
        _: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<crate::CommonGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.inner
            .parse_common_reader_report(self.logical, reader, hash, cancel, emit)
    }
    fn parse_common_local_file_report(
        &self,
        _: &str,
        reader: &mut File,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<crate::CommonGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.inner
            .parse_common_local_file_report(self.logical, reader, hash, cancel, emit)
    }
    fn source_parallelism(&self, _: &str) -> Result<crate::SourceParallelism, AppError> {
        self.inner.source_parallelism(self.logical)
    }
    fn identity(&self) -> ParserIdentity<'_> {
        self.inner.identity()
    }
    fn timestamp_context(&self) -> Option<&str> {
        self.inner.timestamp_context()
    }
    fn parser_name(&self) -> &'static str {
        self.inner.parser_name()
    }
    fn streaming_version(&self) -> &'static str {
        self.inner.streaming_version()
    }
    fn identity_for_source(&self, _: &str) -> Result<ParserIdentity<'_>, AppError> {
        self.inner.identity_for_source(self.logical)
    }
    fn version_for_source(&self, _: &str) -> Result<&'static str, AppError> {
        self.inner.version_for_source(self.logical)
    }
    fn prefers_local_file(&self, _: &str, sample: &[u8]) -> bool {
        self.inner.prefers_local_file(self.logical, sample)
    }
    fn partition_profile_for_source(
        &self,
        _: &str,
        row: &GraphRecord,
    ) -> Result<PartitionProfile, AppError> {
        self.inner.partition_profile_for_source(self.logical, row)
    }
    fn parse_reader(
        &self,
        _: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        self.inner
            .parse_reader(self.logical, reader, hash, cancel, emit)
    }
    fn parse_reader_report(
        &self,
        _: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.inner
            .parse_reader_report(self.logical, reader, hash, cancel, emit)
    }
    fn parse_local_file_report(
        &self,
        _: &str,
        reader: &mut File,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.inner
            .parse_local_file_report(self.logical, reader, hash, cancel, emit)
    }
    fn parse_indexed_reader_report(
        &self,
        _: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<IndexedGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.inner
            .parse_indexed_reader_report(self.logical, reader, hash, cancel, emit)
    }
    fn parse_indexed_local_file_report(
        &self,
        _: &str,
        reader: &mut File,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<IndexedGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.inner
            .parse_indexed_local_file_report(self.logical, reader, hash, cancel, emit)
    }
}
