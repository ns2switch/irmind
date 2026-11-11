//! Bind parser semantics and provenance to the logical source, not its spool.
use crate::{AppError, ParserIdentity, StreamingEventParser};

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
}
