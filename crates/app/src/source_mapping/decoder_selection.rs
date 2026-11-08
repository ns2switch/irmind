//! Metadata for the existing custody/scheduling API; it never normalizes a record.
use crate::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParserConfidence,
    ParserIdentity, SourceDecoder, SourceParallelism, StreamingEventParser,
};
use irmind_domain::Tainted;
use std::{io::Read, sync::Arc};

pub struct SourceDecoderSelection {
    decoder: Arc<dyn SourceDecoder>,
}
impl SourceDecoderSelection {
    pub fn new(decoder: Arc<dyn SourceDecoder>) -> Self {
        Self { decoder }
    }
}
impl StreamingEventParser for SourceDecoderSelection {
    fn parser_name(&self) -> &'static str {
        "source-decoder-selection"
    }
    fn streaming_version(&self) -> &'static str {
        "source-decoder-selection-v1"
    }
    fn identity(&self) -> ParserIdentity<'_> {
        self.decoder.identity()
    }
    fn identity_for_source(&self, _: &str) -> Result<ParserIdentity<'_>, AppError> {
        Ok(self.decoder.identity())
    }
    fn source_parallelism(&self, _: &str) -> Result<SourceParallelism, AppError> {
        Ok(self.decoder.source_parallelism())
    }
    fn prefers_local_file(&self, source: &str, sample: &[u8]) -> bool {
        self.decoder.needs_random_access(source, sample)
    }
    fn parse_reader(
        &self,
        _: &str,
        _: &mut dyn Read,
        _: [u8; 32],
        _: &CancellationToken,
        _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Err(unsupported())
    }
}
impl EventParser for SourceDecoderSelection {
    fn version(&self) -> &'static str {
        "source-decoder-selection-v1"
    }
    fn parse_each(
        &self,
        _: &str,
        _: &[u8],
        _: &CancellationToken,
        _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Err(unsupported())
    }
}
impl LogParser for SourceDecoderSelection {
    fn detect(&self, _: &str, _: &[u8]) -> Option<ParserConfidence> {
        None
    }
}
fn unsupported() -> AppError {
    AppError::Policy("this source decoder requires the selected mapping pipeline; legacy projection is unavailable".into())
}
