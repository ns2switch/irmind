//! A fail-closed composition placeholder for minimal builds without parsers.
use irmind_app::StreamingEventParser;

pub(crate) struct JsonParser;

impl StreamingEventParser for JsonParser {
    fn streaming_version(&self) -> &'static str {
        "unavailable"
    }
    fn parser_name(&self) -> &'static str {
        "parser-json"
    }
}
