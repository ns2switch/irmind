use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_named_envelope_source},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;
pub struct GcpFlowSourceDecoder;
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let log = fields
        .field("logName")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let log = log.to_ascii_lowercase();
    if !log.starts_with("projects/")
        || !log.contains("/logs/")
        || !(log.ends_with("%2fvpc_flows") || log.ends_with("/vpc_flows"))
    {
        return Err(invalid());
    }
    let payload = fields.field("jsonPayload").ok_or_else(invalid)?;
    let connection = payload.field("connection").ok_or_else(invalid)?;
    if !["src_ip", "dest_ip"].iter().all(|key| {
        connection
            .field(key)
            .and_then(SourceValue::as_text)
            .is_some()
    }) {
        return Err(invalid());
    }
    let time = payload
        .field("start_time")
        .or_else(|| fields.field("timestamp"))
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::from_rfc3339(time, false).map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("gcp-vpc-flow", "gcp-flow-source-v1", BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
impl SourceDecoder for GcpFlowSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-gcp-flow",
            version: "gcp-flow-source-v1",
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
        decode_json_named_envelope_source(
            input.into_reader(),
            self.identity(),
            budget,
            &["entries"],
            &prepare,
            emit,
        )
    }
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let cancel = irmind_app::CancellationToken::new();
    let mut input = std::io::Cursor::new(sample);
    let mut frames = JsonFrames::new(&mut input, &cancel)
        .with_record_array_keys(&["entries"])
        .ok()?;
    let frame = frames.next_frame().ok()??;
    let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
    prepare(fields).ok().map(|_| 98)
}
