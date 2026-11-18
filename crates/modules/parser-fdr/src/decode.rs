use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceMetadata, SourceRecordV1,
        SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, text_frame},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedInstant, IndexedTime, Tainted, TimePrecision};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read},
};
pub struct FdrSourceDecoder;
const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn native(fields: &SourceValue) -> bool {
    fields
        .field("event_simpleName")
        .and_then(SourceValue::as_text)
        .is_some_and(|v| !v.is_empty() && v.len() <= 256)
        && ["aid", "cid"].into_iter().all(|key| {
            fields
                .field(key)
                .and_then(SourceValue::as_text)
                .is_some_and(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        })
}
fn prepare(bytes: &[u8]) -> Result<DecodedSourceFrame, AppError> {
    let fields = decode_json_fields(bytes, SourceJsonLimits::default()).map_err(|_| invalid())?;
    if !native(&fields) {
        return Err(invalid());
    }
    let raw = match fields.field("timestamp") {
        Some(SourceValue::Text(v)) => v.as_str(),
        Some(SourceValue::Number(v)) => v.as_str(),
        _ => return Err(invalid()),
    };
    if raw.is_empty() || raw.len() > 20 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let millis = raw.parse::<i64>().map_err(|_| invalid())?;
    let instant = IndexedInstant::new(millis.checked_mul(1000).ok_or_else(invalid)?, 0)
        .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(
            IndexedTime::new(instant, TimePrecision::Millisecond, false).map_err(|_| invalid())?,
        ),
        format: SourceFormatV1::try_new("falcon-fdr", "fdr-source-v1", BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
impl SourceDecoder for FdrSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-fdr",
            version: "fdr-source-v1",
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
        let input = input.into_reader();
        let mut reader = BufReader::new(input.reader);
        if reader
            .fill_buf()
            .map_err(|_| invalid())?
            .starts_with(&[0x1f, 0x8b])
        {
            let compressed = crate::gzip::bounded(reader, input.metadata.cancel);
            let gzip = flate2::read::MultiGzDecoder::new(compressed);
            let mut decoded = crate::gzip::bounded(gzip, input.metadata.cancel);
            let mut callback_failed = false;
            let result = lines(&mut decoded, input.metadata, true, budget, &mut |record| {
                let result = emit(record);
                callback_failed |= result.is_err();
                result
            });
            if callback_failed {
                return result;
            }
            if input.metadata.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if decoded.exceeded() || decoded.inner().get_ref().exceeded() {
                return Err(AppError::Fixed(FixedAppError::SourceLimit));
            }
            result
        } else {
            lines(&mut reader, input.metadata, false, budget, emit)
        }
    }
}
fn lines(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    compressed: bool,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut output = SourceFrameEmitter::new(metadata, FdrSourceDecoder.identity());
    let mut offset = 0;
    output.decode_frames(
        budget,
        || loop {
            let Some((bytes, size)) =
                text_frame(&mut reader, metadata.cancel, MAX_SOURCE - offset)?
            else {
                return Ok(None);
            };
            let start = offset;
            offset += size;
            if bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            return Ok(Some((bytes, (!compressed).then_some(start), ())));
        },
        |bytes, ()| prepare(bytes),
        |()| 0,
        emit,
    )?;
    Ok(output.finish())
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let decoded;
    let bytes = if sample.starts_with(&[0x1f, 0x8b]) {
        decoded = crate::gzip::sample(sample);
        &decoded
    } else {
        sample
    };
    let cancel = irmind_app::CancellationToken::new();
    let mut reader = bytes;
    let mut frames = JsonFrames::new(&mut reader, &cancel);
    let frame = frames.next_frame().ok()??;
    let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
    (native(&fields) && fields.field("timestamp").is_some()).then_some(98)
}
