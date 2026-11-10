//! Original source fields only; classifications and extraction live in mapping modules.
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeAnnotationsV1, DecodeBudget, DecodeInput, SourceDiscriminator, SourceFormatV1,
        SourceInput, SourceMetadata, SourceRecordV1, SourceValue,
        json::{JsonFrame, JsonFrames, SourceJsonLimits, decode_json_fields},
        ordered_decode::decode_ordered,
    },
};
use irmind_domain::{EventOrigin, EvidenceHash, IndexedTime, ParserLocation, Provenance, Tainted};
use std::collections::BTreeMap;

pub struct JsonSourceDecoder;
impl SourceDecoder for JsonSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-json",
            version: "json-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        decode(input, DecodeBudget::sequential(), emit)
    }

    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        decode(input.into_reader(), budget, emit)
    }
}

fn decode(
    SourceInput { metadata, reader }: SourceInput<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut frames = JsonFrames::new(reader, metadata.cancel);
    let mut seen = 0u64;
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    decode_ordered(
        budget,
        metadata.cancel,
        || {
            let Some(frame) = frames.next_frame()? else {
                return Ok(None);
            };
            seen += 1;
            if seen > 10_000_000 {
                return Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit));
            }
            // Account for both original bytes and the parsed field tree.
            let weight = frame.bytes().len().saturating_mul(64);
            Ok(Some((frame, weight)))
        },
        prepare_frame,
        |(frame, parsed)| {
            let record = parsed.and_then(|(fields, time)| {
                materialize_frame(metadata, &frame, report.accepted, fields, time)
            });
            match record {
                Ok(record) => {
                    let location = ParserLocation::new(
                        metadata.source.reference(),
                        "parser-json",
                        frame.offset(),
                    )
                    .map_err(|_| invalid())?;
                    emit(Tainted::from_external(
                        record,
                        Provenance::new(
                            metadata.evidence_hash,
                            Some(report.accepted as u64),
                            metadata.source.kind(),
                        )
                        .with_parser_location(location),
                    ))?;
                    report.accepted += 1;
                }
                Err(_) => reject(&mut report, frame.bytes()),
            }
            Ok(())
        },
    )?;
    Ok(report)
}

fn prepare_frame(
    frame: JsonFrame,
) -> (
    JsonFrame,
    Result<(SourceValue, Option<IndexedTime>), AppError>,
) {
    let result = if frame.oversized() {
        Err(invalid())
    } else {
        decode_json_fields(frame.bytes(), SourceJsonLimits::default())
            .map_err(|_| invalid())
            .and_then(|fields| {
                let time = timestamp(&fields)?;
                Ok((fields, time))
            })
    };
    (frame, result)
}

fn materialize_frame(
    metadata: SourceMetadata<'_>,
    frame: &JsonFrame,
    index: usize,
    fields: SourceValue,
    timestamp: Option<IndexedTime>,
) -> Result<SourceRecordV1, AppError> {
    let origin = EventOrigin::try_new(
        EvidenceHash::from_bytes(metadata.evidence_hash),
        index as u64,
        Some(frame.offset()),
        "parser-json",
        "json-source-v1",
    )
    .map_err(|_| invalid())?;
    let mut discriminators = BTreeMap::new();
    if let Some(provider) = fields.field("provider").and_then(SourceValue::as_text) {
        discriminators.insert(SourceDiscriminator::Provider, provider.into());
    }
    let format =
        SourceFormatV1::try_new("json", "source-json-v1", discriminators).map_err(|_| invalid())?;
    SourceRecordV1::try_from_source(
        origin,
        metadata.source.clone(),
        timestamp,
        format,
        fields,
        DecodeAnnotationsV1::default(),
    )
    .map_err(|_| invalid())
}
fn timestamp(fields: &SourceValue) -> Result<Option<IndexedTime>, AppError> {
    let value = [
        "event_time",
        "eventTime",
        "timestamp",
        "time",
        "eventTimestamp",
        "createdDateTime",
    ]
    .iter()
    .find_map(|key| fields.field(key));
    let Some(value) = value
        .and_then(SourceValue::as_text)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    IndexedTime::from_rfc3339(value, false)
        .map(Some)
        .map_err(|_| invalid())
}
fn reject(report: &mut ParseReport, bytes: &[u8]) {
    report.rejected += 1;
    if report.samples.len() < 3 {
        report.samples.push(
            String::from_utf8_lossy(&bytes[..bytes.len().min(256)])
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
