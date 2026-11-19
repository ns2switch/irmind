use irmind_app::{
    AppError, CancellationToken, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceDiscriminator, SourceFormatV1, SourceInput,
        SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source, source_datetime},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;

pub struct MacosSourceDecoder;

#[derive(Clone, Copy)]
enum Format<'a> {
    UnifiedLog,
    EndpointSecurity { schema: &'a str, event: &'a str },
}

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

fn text<'a>(fields: &'a SourceValue, key: &str) -> Option<&'a str> {
    fields.field(key).and_then(SourceValue::as_text)
}

fn small_number<'a>(fields: &'a SourceValue, key: &str) -> Option<&'a str> {
    match fields.field(key)? {
        SourceValue::Number(value) if value.as_str().parse::<u32>().is_ok() => Some(value.as_str()),
        _ => None,
    }
}

fn identify(fields: &SourceValue) -> Option<Format<'_>> {
    if text(fields, "timestamp").is_some()
        && text(fields, "eventType").is_some_and(|value| !value.is_empty())
        && text(fields, "eventMessage").is_some()
        && (small_number(fields, "processID").is_some()
            || text(fields, "processImagePath").is_some()
            || text(fields, "bootUUID").is_some())
    {
        return Some(Format::UnifiedLog);
    }
    let schema = small_number(fields, "schema_version")?;
    let SourceValue::Object(events) = fields.field("event")? else {
        return None;
    };
    let (event, _) = events.first_key_value()?;
    if schema != "0"
        && text(fields, "time").is_some()
        && small_number(fields, "version").is_some()
        && small_number(fields, "event_type").is_some()
        && matches!(fields.field("process"), Some(SourceValue::Object(_)))
        && events.len() == 1
    {
        return Some(Format::EndpointSecurity { schema, event });
    }
    None
}

fn unified_time(raw: &str) -> Result<IndexedTime, AppError> {
    if raw.len() > 128 || !raw.is_ascii() {
        return Err(invalid());
    }
    // log show uses the numeric suffix ±HHMM in some versions.
    if let Some(offset) = raw.len().checked_sub(5)
        && offset >= 19
        && matches!(raw.as_bytes()[offset], b'+' | b'-')
        && raw.as_bytes()[offset + 1..].iter().all(u8::is_ascii_digit)
    {
        let (hour, minute) = raw.split_at(raw.len() - 2);
        return source_datetime(&format!("{hour}:{minute}"), None);
    }
    source_datetime(raw, None)
}

fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let mut discriminators = BTreeMap::new();
    let (dataset, schema, timestamp) = match identify(&fields).ok_or_else(invalid)? {
        Format::UnifiedLog => (
            "macos-unified-log",
            "log-show-json",
            unified_time(text(&fields, "timestamp").ok_or_else(invalid)?)?,
        ),
        Format::EndpointSecurity { schema, event } => {
            if !event.is_empty() && event.len() <= 256 {
                discriminators.insert(SourceDiscriminator::RecordType, event.to_owned());
            }
            (
                "macos-eslogger",
                schema,
                source_datetime(text(&fields, "time").ok_or_else(invalid)?, None)?,
            )
        }
    };
    let format = SourceFormatV1::try_new(dataset, schema, discriminators).map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format,
    })
}

impl SourceDecoder for MacosSourceDecoder {
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
        decode_json_source(input.into_reader(), self.identity(), budget, &prepare, emit)
    }
}

pub(super) fn detect(sample: &[u8]) -> bool {
    let mut reader = &sample[..sample.len().min(65_536)];
    let cancel = CancellationToken::new();
    let mut frames = JsonFrames::new(&mut reader, &cancel).without_record_wrappers();
    frames
        .next_frame()
        .ok()
        .flatten()
        .and_then(|frame| decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok())
        .is_some_and(|fields| identify(&fields).is_some())
}
