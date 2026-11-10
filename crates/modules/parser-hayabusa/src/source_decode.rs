//! Original CSV/JSON fields and timestamps; interpretation belongs to a mapping module.
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceDecoderSelection, SourceDiscriminator, SourceFormatV1, SourceInput, SourceMetadata,
        SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, decode_json_source, source_datetime},
    },
};
use irmind_domain::Tainted;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    sync::Arc,
};
pub struct HayabusaSourceDecoder;
impl SourceDecoder for HayabusaSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-hayabusa",
            version: "hayabusa-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut reader = BufReader::new(input.reader);
        if reader
            .fill_buf()
            .map_err(|_| invalid())?
            .starts_with(b"Timestamp,")
        {
            csv_decode(&mut reader, input.metadata, emit)
        } else {
            let context = input.metadata.time_context;
            decode_json_source(
                SourceInput {
                    metadata: input.metadata,
                    reader: &mut reader,
                },
                self.identity(),
                &mut |fields| frame(fields, context, "json", "timeline"),
                emit,
            )
        }
    }
}
fn csv_decode(
    reader: &mut impl BufRead,
    metadata: SourceMetadata<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let (header, size) = super::csv::csv_record(reader, metadata.cancel)?;
    if size == 0 || header.len() > irmind_domain::SOURCE_MAX_BYTES {
        return Err(invalid());
    }
    let headers = super::csv::decode_csv(&header)?;
    if headers.len() > 1024 || headers.iter().collect::<BTreeSet<_>>().len() != headers.len() {
        return Err(invalid());
    }
    if !["Timestamp", "RuleTitle", "Computer"]
        .iter()
        .all(|k| headers.iter().any(|v| v == *k))
    {
        return Err(invalid());
    }
    let dataset = "timeline";
    let mut state = SourceFrameEmitter::new(metadata, HayabusaSourceDecoder.identity());
    let mut offset = size;
    loop {
        let (bytes, size) = super::csv::csv_record(reader, metadata.cancel)?;
        if size == 0 {
            return Ok(state.finish());
        }
        let start = offset;
        offset = offset.checked_add(size).ok_or_else(invalid)?;
        if offset > 50 * 1024 * 1024 * 1024 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit));
        }
        let decoded = csv_fields(&headers, &bytes)
            .and_then(|fields| frame(fields, metadata.time_context, "csv", dataset));
        state.frame(&bytes, Some(start), decoded, emit)?;
    }
}
fn csv_fields(headers: &::csv::StringRecord, bytes: &[u8]) -> Result<SourceValue, AppError> {
    if bytes.len() > irmind_domain::SOURCE_MAX_BYTES {
        return Err(invalid());
    }
    let values = super::csv::decode_csv(bytes)?;
    if values.len() != headers.len() {
        return Err(invalid());
    }
    SourceValue::object(
        headers
            .iter()
            .zip(values.iter())
            .map(|(k, v)| (k.to_owned(), SourceValue::Text(v.to_owned())))
            .collect(),
    )
    .map_err(|_| invalid())
}
fn frame(
    fields: SourceValue,
    context: Option<&irmind_app::ParserTimeContext>,
    encoding: &str,
    dataset: &str,
) -> Result<DecodedSourceFrame, AppError> {
    let raw = fields
        .field("Timestamp")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = source_datetime(raw, context)?;
    let format = SourceFormatV1::try_new(
        &format!("hayabusa-{encoding}"),
        "hayabusa-source-v1",
        BTreeMap::from([(SourceDiscriminator::Dataset, dataset.into())]),
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
        SourceDecoderSelection::new(Arc::new(HayabusaSourceDecoder))
            .with_detector(|source, sample| super::HayabusaParser.detect(source, sample))
            .with_time_detector(|source, sample| {
                super::HayabusaParser.time_context_requirement(source, sample)
            }),
    )
}
