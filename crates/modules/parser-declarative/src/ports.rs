use crate::{AppError, DeclarativeParser};
use irmind_app::{LogParser, ParserConfidence, ParserIdentity, StreamingEventParser};

impl StreamingEventParser for DeclarativeParser {
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
}

impl LogParser for DeclarativeParser {
    fn description(&self) -> &str {
        self.description()
    }
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        self.detect_sample(sample)
    }
}
