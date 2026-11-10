//! Original EVE JSON fields and exact timestamps, without event interpretation.
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceDecoderSelection, SourceDiscriminator, SourceFormatV1, SourceInput, SourceRecordV1,
        SourceValue,
        framed::{DecodedSourceFrame, decode_json_source},
    },
};
use irmind_domain::Tainted;
use std::{collections::BTreeMap, sync::Arc};
pub struct SuricataSourceDecoder;
impl SourceDecoder for SuricataSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-suricata",
            version: "suricata-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        decode_json_source(input, self.identity(), &mut frame, emit)
    }
}
fn frame(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let raw = fields
        .field("timestamp")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = timestamp(raw)?;
    let kind = fields
        .field("event_type")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    if !matches!(
        kind,
        "alert" | "flow" | "dns" | "http" | "tls" | "fileinfo" | "anomaly"
    ) {
        return Err(invalid());
    }
    let format = SourceFormatV1::try_new(
        "suricata-eve",
        "suricata-source-v1",
        BTreeMap::from([(SourceDiscriminator::Dataset, kind.into())]),
    )
    .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format,
    })
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        SourceDecoderSelection::new(Arc::new(SuricataSourceDecoder))
            .with_detector(|source, sample| crate::SuricataParser.detect(source, sample)),
    )
}

pub(super) fn timestamp(raw: &str) -> Result<irmind_app::IndexedTime, AppError> {
    if raw.len() > 64 || !raw.is_ascii() {
        return Err(invalid());
    }
    let mut normalized = raw.to_owned();
    if let Some(zone) = raw.get(raw.len().saturating_sub(5)..)
        && zone.len() == 5
        && zone.starts_with(['+', '-'])
        && zone.as_bytes()[1..].iter().all(u8::is_ascii_digit)
    {
        normalized.insert(normalized.len() - 2, ':');
    }
    irmind_app::IndexedTime::from_rfc3339(&normalized, false).map_err(|_| invalid())
}
