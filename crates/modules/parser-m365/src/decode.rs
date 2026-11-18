use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{
            DecodedSourceFrame, SourceFrameEmitter, csv_frame, csv_values,
            decode_json_envelope_source, source_datetime,
        },
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::Tainted;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
};
pub struct M365SourceDecoder;
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn inner(fields: SourceValue) -> Result<SourceValue, AppError> {
    match fields.field("AuditData") {
        Some(SourceValue::Text(value)) => {
            decode_json_fields(value.as_bytes(), SourceJsonLimits::default()).map_err(|_| invalid())
        }
        Some(SourceValue::Object(_)) => fields.field("AuditData").cloned().ok_or_else(invalid),
        Some(_) => Err(invalid()),
        None => Ok(fields),
    }
}
fn native(fields: &SourceValue) -> bool {
    fields
        .field("Operation")
        .and_then(SourceValue::as_text)
        .is_some()
        && fields
            .field("CreationTime")
            .and_then(SourceValue::as_text)
            .is_some()
        && (fields.field("RecordType").is_some() || fields.field("Workload").is_some())
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let fields = inner(fields)?;
    if !native(&fields) {
        return Err(invalid());
    }
    let time = fields
        .field("CreationTime")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    // The documented audit CreationTime is UTC even when the export omits Z.
    let timestamp =
        source_datetime(time, None).or_else(|_| source_datetime(&format!("{time}Z"), None))?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("m365-audit", "m365-source-v1", BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
impl SourceDecoder for M365SourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-m365",
            version: "m365-source-v1",
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
        let metadata = input.metadata;
        let prefix = reader.fill_buf().map_err(|_| invalid())?.trim_ascii_start();
        if matches!(prefix.first(), Some(b'{' | b'[')) {
            return decode_json_envelope_source(
                SourceInput {
                    metadata,
                    reader: &mut reader,
                },
                self.identity(),
                budget,
                &prepare,
                emit,
            );
        }
        let (header, mut offset) =
            csv_frame(&mut reader, metadata.cancel, 50 * 1024 * 1024 * 1024)?
                .ok_or_else(invalid)?;
        let mut headers = csv_values(&header)?;
        if let Some(first) = headers.first_mut() {
            *first = first.trim_start_matches('\u{feff}').to_owned();
        }
        if !headers.iter().any(|h| h == "AuditData")
            || headers.iter().collect::<BTreeSet<_>>().len() != headers.len()
        {
            return Err(invalid());
        }
        let index = headers
            .iter()
            .position(|h| h == "AuditData")
            .ok_or_else(invalid)?;
        let mut output = SourceFrameEmitter::new(metadata, self.identity());
        output.decode_frames(
            budget,
            || {
                let Some((bytes, size)) = csv_frame(
                    &mut reader,
                    metadata.cancel,
                    (50u64 * 1024 * 1024 * 1024).saturating_sub(offset),
                )?
                else {
                    return Ok(None);
                };
                let start = offset;
                offset = offset.checked_add(size).ok_or_else(invalid)?;
                Ok(Some((bytes, Some(start), ())))
            },
            |bytes, ()| {
                let values = csv_values(bytes)?;
                if values.len() != headers.len() {
                    return Err(invalid());
                }
                let fields =
                    decode_json_fields(values[index].as_bytes(), SourceJsonLimits::default())
                        .map_err(|_| invalid())?;
                prepare(fields)
            },
            |()| header.len(),
            emit,
        )?;
        Ok(output.finish())
    }
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let cancel = irmind_app::CancellationToken::new();
    let mut reader = std::io::Cursor::new(sample);
    if sample
        .trim_ascii_start()
        .first()
        .is_some_and(|b| matches!(b, b'{' | b'['))
    {
        let mut frames = JsonFrames::new(&mut reader, &cancel);
        let frame = frames.next_frame().ok()??;
        let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
        return prepare(fields).ok().map(|_| 98);
    }
    let (header, _) = csv_frame(&mut reader, &cancel, 65536).ok()??;
    let mut headers = csv_values(&header).ok()?;
    if let Some(first) = headers.first_mut() {
        *first = first.trim_start_matches('\u{feff}').to_owned();
    }
    let i = headers.iter().position(|h| h == "AuditData")?;
    let (row, _) = csv_frame(&mut reader, &cancel, 65536).ok()??;
    let values = csv_values(&row).ok()?;
    let fields = decode_json_fields(values.get(i)?.as_bytes(), SourceJsonLimits::default()).ok()?;
    prepare(fields).ok().map(|_| 98)
}
