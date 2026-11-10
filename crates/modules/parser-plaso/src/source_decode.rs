//! Original Plaso fields and timestamp only; extraction is a separate mapping.
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceDecoderSelection, SourceFormatV1, SourceInput,
        SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source, source_datetime},
    },
};
use irmind_domain::Tainted;
use std::{collections::BTreeMap, sync::Arc};
pub struct PlasoSourceDecoder;
impl SourceDecoder for PlasoSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-plaso",
            version: "plaso-source-v1",
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
        let context = input.metadata.time_context;
        decode_json_source(
            input,
            self.identity(),
            budget,
            &|fields| decode(fields, context),
            emit,
        )
    }
}
fn decode(
    fields: SourceValue,
    context: Option<&irmind_app::ParserTimeContext>,
) -> Result<DecodedSourceFrame, AppError> {
    if first(&fields, &["data_type", "parser"]).is_none() {
        return Err(invalid());
    }
    let timestamp = timestamp(&fields, context)?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("plaso", "plaso-source-v1", BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
fn timestamp(
    fields: &SourceValue,
    context: Option<&irmind_app::ParserTimeContext>,
) -> Result<irmind_domain::IndexedTime, AppError> {
    use irmind_domain::{IndexedInstant, IndexedTime, TimePrecision};
    let declared = first(fields, &["datetime"])
        .map(|raw| source_datetime(raw, context))
        .transpose()?;
    let micros = match fields.field("timestamp") {
        None | Some(SourceValue::Null) => None,
        Some(SourceValue::Number(n)) => Some(n.as_str().parse::<i64>().map_err(|_| invalid())?),
        _ => return Err(invalid()),
    };
    let Some(micros) = micros else {
        return declared.ok_or_else(invalid);
    };
    let instant = IndexedInstant::new(micros, 0).map_err(|_| invalid())?;
    if let Some(declared) = declared {
        let unit = match declared.precision() {
            TimePrecision::Second => 1_000_000,
            TimePrecision::Millisecond => 1000,
            _ => 1,
        };
        if instant.unix_micros().div_euclid(unit)
            != declared.instant().unix_micros().div_euclid(unit)
        {
            return Err(invalid());
        }
        if declared.precision() == TimePrecision::Nanosecond {
            return Ok(declared);
        }
    }
    IndexedTime::new(instant, TimePrecision::Microsecond, false).map_err(|_| invalid())
}
fn first<'a>(fields: &'a SourceValue, paths: &[&str]) -> Option<&'a str> {
    paths.iter().find_map(|path| {
        path.split('.')
            .try_fold(fields, |v, k| v.field(k))
            .and_then(SourceValue::as_text)
    })
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        SourceDecoderSelection::new(Arc::new(PlasoSourceDecoder))
            .with_detector(|source, sample| super::PlasoParser.detect(source, sample))
            .with_time_detector(|source, sample| {
                super::PlasoParser.time_context_requirement(source, sample)
            }),
    )
}
