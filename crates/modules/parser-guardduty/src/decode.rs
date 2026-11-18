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
pub struct GuardDutySourceDecoder;
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn native(fields: &SourceValue) -> Option<bool> {
    for sdk in [false, true] {
        let keys = if sdk {
            ["AccountId", "Id", "Type", "Region", "Resource"]
        } else {
            ["accountId", "id", "type", "region", "resource"]
        };
        if keys[..4]
            .iter()
            .all(|key| fields.field(key).and_then(SourceValue::as_text).is_some())
            && matches!(fields.field(keys[4]), Some(SourceValue::Object(_)))
        {
            return Some(sdk);
        }
    }
    None
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let fields = if fields.field("source").and_then(SourceValue::as_text) == Some("aws.guardduty") {
        fields.field("detail").cloned().ok_or_else(invalid)?
    } else {
        fields
    };
    let sdk = native(&fields).ok_or_else(invalid)?;
    let time = fields
        .field(if sdk { "UpdatedAt" } else { "updatedAt" })
        .or_else(|| fields.field(if sdk { "CreatedAt" } else { "createdAt" }))
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::from_rfc3339(time, false).map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new(
            if sdk {
                "guardduty-sdk"
            } else {
                "guardduty-json"
            },
            "guardduty-source-v1",
            BTreeMap::new(),
        )
        .map_err(|_| invalid())?,
    })
}
impl SourceDecoder for GuardDutySourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-guardduty",
            version: "guardduty-source-v1",
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
            &["findings", "Findings"],
            &prepare,
            emit,
        )
    }
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let cancel = irmind_app::CancellationToken::new();
    let mut reader = std::io::Cursor::new(sample);
    let mut frames = JsonFrames::new(&mut reader, &cancel)
        .with_record_array_keys(&["findings", "Findings"])
        .ok()?;
    let frame = frames.next_frame().ok()??;
    let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
    prepare(fields).ok().map(|_| 98)
}
