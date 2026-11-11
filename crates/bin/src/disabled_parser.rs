//! A fail-closed composition placeholder for minimal builds without parsers.
use irmind_app::{AppError, CancellationToken, EventParser, GraphRecord, StreamingEventParser};
use irmind_domain::Tainted;

pub(crate) struct JsonParser;

impl EventParser for JsonParser {
    fn version(&self) -> &'static str {
        "unavailable"
    }

    fn parse_each(
        &self,
        _source: &str,
        _bytes: &[u8],
        _cancel: &CancellationToken,
        _emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Err(AppError::Policy("parser-json is not compiled".into()))
    }
}

impl StreamingEventParser for JsonParser {
    fn streaming_version(&self) -> &'static str {
        "unavailable"
    }
    fn parser_name(&self) -> &'static str {
        "parser-json"
    }
}
