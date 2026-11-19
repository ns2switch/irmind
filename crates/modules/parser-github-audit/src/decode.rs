use irmind_app::{
    AppError, CancellationToken, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceMetadata, SourceRecordV1,
        SourceValue,
        framed::{
            DecodedSourceFrame, SourceFrameEmitter, csv_frame, csv_values, decode_json_source,
        },
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedInstant, IndexedTime, Tainted, TimePrecision};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Cursor},
};

pub struct GitHubAuditSourceDecoder;

const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

fn text<'a>(fields: &'a SourceValue, key: &str) -> Option<&'a str> {
    fields
        .field(key)
        .and_then(SourceValue::as_text)
        .filter(|text| !text.is_empty())
}

fn timestamp(fields: &SourceValue) -> Result<IndexedTime, AppError> {
    let raw = ["created_at", "@timestamp"]
        .into_iter()
        .filter_map(|key| fields.field(key))
        .find(|value| !matches!(value, SourceValue::Null) && value.as_text() != Some(""))
        .and_then(|value| match value {
            SourceValue::Text(value) => Some(value.as_str()),
            SourceValue::Number(value) => Some(value.as_str()),
            _ => None,
        })
        .filter(|value| value.len() <= 128)
        .ok_or_else(invalid)?;
    if let Ok(instant) = IndexedTime::from_rfc3339(raw, false) {
        return Ok(instant);
    }
    let millis = raw.parse::<i64>().map_err(|_| invalid())?;
    let instant = IndexedInstant::new(millis.checked_mul(1000).ok_or_else(invalid)?, 0)
        .map_err(|_| invalid())?;
    IndexedTime::new(instant, TimePrecision::Millisecond, false).map_err(|_| invalid())
}

fn prepare(fields: SourceValue, format: &str) -> Result<DecodedSourceFrame, AppError> {
    let action = text(&fields, "action").ok_or_else(invalid)?;
    if action.len() > 256
        || action.split_once('.').is_none_or(|(category, event)| {
            category.is_empty()
                || event.is_empty()
                || !action
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
        || !(text(&fields, "_document_id").is_some()
            || (text(&fields, "actor").is_some()
                && ["org", "repo", "business"]
                    .iter()
                    .any(|key| text(&fields, key).is_some())))
    {
        return Err(invalid());
    }
    let timestamp = timestamp(&fields)?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new(format, super::VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}

fn header(bytes: &[u8]) -> Result<Vec<String>, AppError> {
    let fields = csv_values(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))?;
    let names: BTreeSet<_> = fields.iter().map(String::as_str).collect();
    if names.len() != fields.len()
        || !names.contains("action")
        || !(names.contains("created_at") || names.contains("@timestamp"))
        || !(names.contains("_document_id")
            || (names.contains("actor")
                && ["org", "repo", "business"]
                    .iter()
                    .any(|key| names.contains(key))))
    {
        return Err(invalid());
    }
    Ok(fields)
}

fn csv_record(bytes: &[u8], headers: &[String]) -> Result<DecodedSourceFrame, AppError> {
    let values = csv_values(bytes)?;
    if values.len() != headers.len() {
        return Err(invalid());
    }
    prepare(
        SourceValue::object(
            headers
                .iter()
                .cloned()
                .zip(values.into_iter().map(SourceValue::Text))
                .collect(),
        )
        .map_err(|_| invalid())?,
        "github-audit-csv",
    )
}

fn decode_csv(
    reader: &mut dyn BufRead,
    metadata: SourceMetadata<'_>,
    budget: DecodeBudget,
    identity: ParserIdentity<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let (line, mut offset) = csv_frame(reader, metadata.cancel, MAX_SOURCE)?.ok_or_else(invalid)?;
    let headers = header(&line)?;
    let mut output = SourceFrameEmitter::new(metadata, identity);
    output.decode_frames(
        budget,
        || {
            let Some((bytes, size)) =
                csv_frame(reader, metadata.cancel, MAX_SOURCE.saturating_sub(offset))?
            else {
                return Ok(None);
            };
            let start = offset;
            offset = offset.checked_add(size).ok_or_else(invalid)?;
            Ok(Some((bytes, Some(start), ())))
        },
        |bytes, ()| csv_record(bytes, &headers),
        |()| line.len(),
        emit,
    )?;
    Ok(output.finish())
}

fn is_json(sample: &[u8]) -> bool {
    matches!(sample.trim_ascii_start().first(), Some(b'{' | b'['))
}

impl SourceDecoder for GitHubAuditSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: super::PARSER,
            version: super::VERSION,
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
        if is_json(reader.fill_buf().map_err(|_| invalid())?) {
            return decode_json_source(
                SourceInput {
                    metadata: input.metadata,
                    reader: &mut reader,
                },
                self.identity(),
                budget,
                &|fields| prepare(fields, "github-audit-json"),
                emit,
            );
        }
        decode_csv(&mut reader, input.metadata, budget, self.identity(), emit)
    }
}

pub(super) fn detect(sample: &[u8]) -> bool {
    probe(&sample[..sample.len().min(65_536)]).is_some()
}

fn probe(sample: &[u8]) -> Option<()> {
    let mut reader = Cursor::new(sample);
    let cancellation = CancellationToken::new();
    if is_json(sample) {
        let frame = JsonFrames::new(&mut reader, &cancellation)
            .without_record_wrappers()
            .next_frame()
            .ok()??;
        let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
        prepare(fields, "github-audit-json").ok()?;
    } else {
        let (fields, header_size) = csv_frame(&mut reader, &cancellation, 65_536).ok()??;
        let headers = header(&fields).ok()?;
        let (row, _) = csv_frame(&mut reader, &cancellation, 65_536 - header_size).ok()??;
        csv_record(&row, &headers).ok()?;
    }
    Some(())
}
