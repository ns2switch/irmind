use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_envelope_source},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;
pub struct OktaSourceDecoder;
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    if fields
        .field("eventType")
        .and_then(SourceValue::as_text)
        .is_none()
        || fields
            .field("uuid")
            .and_then(SourceValue::as_text)
            .is_none()
        || !matches!(fields.field("actor"), Some(SourceValue::Object(_)))
    {
        return Err(invalid());
    }
    let time = fields
        .field("published")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::from_rfc3339(time, false).map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("okta-system-log", "okta-source-v1", BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
impl SourceDecoder for OktaSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-okta",
            version: "okta-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_with_budget(DecodeInput::Reader(input), DecodeBudget::sequential(), emit)
    }
    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        decode_json_envelope_source(input.into_reader(), self.identity(), budget, &prepare, emit)
    }
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let cancel = irmind_app::CancellationToken::new();
    let mut reader = std::io::Cursor::new(sample);
    let mut frames = JsonFrames::new(&mut reader, &cancel);
    let first = frames.next_frame().ok()??;
    let fields = decode_json_fields(first.bytes(), SourceJsonLimits::default()).ok()?;
    prepare(fields).ok().map(|_| 98)
}
