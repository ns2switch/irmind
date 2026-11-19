use irmind_app::{
    AppError, CancellationToken, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, decode_json_named_envelope_source},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;

pub struct GoogleWorkspaceSourceDecoder;

const RECORD_ARRAYS: &[&str] = &["items"];
const MAX_EVENTS_PER_ACTIVITY: usize = 128;

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

fn native_time(fields: &SourceValue) -> Result<IndexedTime, AppError> {
    if let Some(kind) = fields.field("kind")
        && !matches!(
            kind.as_text(),
            Some("audit#activity" | "admin#reports#activity")
        )
    {
        return Err(invalid());
    }
    let id = fields.field("id").ok_or_else(invalid)?;
    if !["uniqueQualifier", "applicationName"]
        .into_iter()
        .all(|name| {
            id.field(name)
                .and_then(SourceValue::as_text)
                .is_some_and(|text| !text.is_empty() && text.len() <= 256)
        })
    {
        return Err(invalid());
    }
    if !matches!(fields.field("events"), Some(SourceValue::Array(events))
        if !events.is_empty() && events.len() <= MAX_EVENTS_PER_ACTIVITY)
    {
        return Err(invalid());
    }
    let instant = id
        .field("time")
        .and_then(SourceValue::as_text)
        .filter(|time| time.len() <= 128)
        .ok_or_else(invalid)?;
    IndexedTime::from_rfc3339(instant, false)
        .or_else(|_| IndexedTime::from_epoch_decimal(instant, false))
        .map_err(|_| invalid())
}

fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let timestamp = native_time(&fields)?;
    Ok(DecodedSourceFrame {
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new(
            "google-workspace-activity",
            super::VERSION,
            BTreeMap::new(),
        )
        .map_err(|_| invalid())?,
        fields,
    })
}

fn expand(
    source: &SourceRecordV1,
    output: &mut SourceFrameEmitter<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let SourceValue::Object(fields) = source.fields() else {
        return Err(invalid());
    };
    let Some(SourceValue::Array(events)) = fields.get("events") else {
        return Err(invalid());
    };
    let activity = SourceValue::Object(
        fields
            .iter()
            .filter(|(name, _)| name.as_str() != "events")
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    );
    for event in events {
        let decoded = event_frame(source, &activity, event);
        // The shared offset identifies the original activity. An event inside
        // its JSON array has its own record ordinal, but no claimed byte offset.
        output.frame(
            b"invalid Google Workspace activity event",
            source.origin().offset(),
            decoded,
            emit,
        )?;
    }
    Ok(())
}

fn event_frame(
    source: &SourceRecordV1,
    activity: &SourceValue,
    event: &SourceValue,
) -> Result<DecodedSourceFrame, AppError> {
    if !event
        .field("name")
        .and_then(SourceValue::as_text)
        .is_some_and(|name| !name.is_empty() && name.len() <= 256)
    {
        return Err(invalid());
    }
    Ok(DecodedSourceFrame {
        fields: SourceValue::object(vec![
            ("activity".into(), activity.clone()),
            ("event".into(), event.clone()),
        ])
        .map_err(|_| invalid())?,
        timestamp: source.timestamp(),
        format: source.format().clone(),
    })
}

impl SourceDecoder for GoogleWorkspaceSourceDecoder {
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
        let mut output = SourceFrameEmitter::new(input.metadata, self.identity());
        let activities = decode_json_named_envelope_source(
            input,
            self.identity(),
            budget,
            RECORD_ARRAYS,
            &prepare,
            &mut |record| {
                let mut result = Ok(());
                record.inspect(|source| result = expand(source, &mut output, emit));
                result
            },
        )?;
        let mut report = output.finish();
        report.rejected += activities.rejected;
        report.samples.extend(
            activities
                .samples
                .into_iter()
                .take(3usize.saturating_sub(report.samples.len())),
        );
        Ok(report)
    }
}

pub(super) fn detect(sample: &[u8]) -> bool {
    let mut reader = &sample[..sample.len().min(65_536)];
    let cancel = CancellationToken::new();
    let Ok(mut frames) =
        JsonFrames::new(&mut reader, &cancel).with_record_array_keys(RECORD_ARRAYS)
    else {
        return false;
    };
    frames
        .next_frame()
        .ok()
        .flatten()
        .and_then(|frame| decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok())
        .is_some_and(|fields| native_time(&fields).is_ok())
}
