//! Metadata for the existing custody/scheduling API; it never normalizes a record.
use crate::{
    AppError, LogParser, ParserConfidence, ParserIdentity, SourceDecoder, SourceParallelism,
    StreamingEventParser,
};
use std::sync::Arc;

type Detector = fn(&str, &[u8]) -> Option<ParserConfidence>;
type TimeDetector = fn(&str, &[u8]) -> Result<Option<crate::ParserTimeRequirement>, AppError>;

pub struct SourceDecoderSelection {
    decoder: Arc<dyn SourceDecoder>,
    context: Option<String>,
    detector: Option<Detector>,
    time_detector: Option<TimeDetector>,
    selector: Option<Arc<dyn LogParser>>,
}
impl SourceDecoderSelection {
    pub fn new(decoder: Arc<dyn SourceDecoder>) -> Self {
        Self {
            decoder,
            context: None,
            detector: None,
            time_detector: None,
            selector: None,
        }
    }
}
impl SourceDecoderSelection {
    /// Reuse approved detection while keeping source-pipeline time metadata separate.
    pub fn with_selector(mut self, selector: Arc<dyn LogParser>) -> Result<Self, AppError> {
        if selector.identity() != self.decoder.identity() {
            return Err(unsupported());
        }
        self.selector = Some(selector);
        Ok(self)
    }
    #[must_use]
    pub fn with_detector(mut self, detector: fn(&str, &[u8]) -> Option<ParserConfidence>) -> Self {
        self.detector = Some(detector);
        self
    }
    #[must_use]
    pub fn with_time_detector(mut self, detector: TimeDetector) -> Self {
        self.time_detector = Some(detector);
        self
    }
}
impl StreamingEventParser for SourceDecoderSelection {
    fn timestamp_context(&self) -> Option<&str> {
        self.context.as_deref()
    }
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
}

impl LogParser for SourceDecoderSelection {
    fn description(&self) -> &str {
        self.selector
            .as_ref()
            .map_or("", |selector| selector.description())
    }
    fn with_time_context(
        &self,
        context: &crate::ParserTimeContext,
    ) -> Result<Arc<dyn LogParser>, AppError> {
        Ok(Arc::new(Self {
            decoder: Arc::clone(&self.decoder),
            context: Some(super::source_time_snapshot(context)?),
            detector: self.detector,
            time_detector: self.time_detector,
            selector: self.selector.clone(),
        }))
    }

    fn detect(&self, source: &str, sample: &[u8]) -> Option<ParserConfidence> {
        if let Some(selector) = &self.selector {
            return selector.detect(source, &sample[..sample.len().min(65_536)]);
        }
        self.detector
            .and_then(|detect| detect(source, &sample[..sample.len().min(65_536)]))
    }
    fn time_context_requirement(
        &self,
        source: &str,
        sample: &[u8],
    ) -> Result<Option<crate::ParserTimeRequirement>, AppError> {
        self.time_detector.map_or(Ok(None), |detect| {
            detect(source, &sample[..sample.len().min(65_536)])
        })
    }
}
fn unsupported() -> AppError {
    AppError::Policy("this source decoder requires the selected mapping pipeline; legacy projection is unavailable".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
