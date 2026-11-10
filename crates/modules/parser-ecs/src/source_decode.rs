//! Bounded ECS framing and original fields; semantic interpretation is a mapping.
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeAnnotationsV1, DecodeBudget, DecodeInput, SourceDecoderSelection, SourceFormatV1,
        SourceInput, SourceRecordV1, SourceValue,
        json::{SourceJsonLimits, decode_json_fields},
        ordered_decode::decode_ordered,
    },
};
use irmind_domain::{EventOrigin, EvidenceHash, IndexedTime, ParserLocation, Provenance, Tainted};
use std::{collections::BTreeMap, io::BufReader, sync::Arc};

pub struct EcsSourceDecoder;
impl SourceDecoder for EcsSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-ecs",
            version: "ecs-source-v1",
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
        decode(input.into_reader(), budget, emit)
    }
}

fn decode(
    SourceInput { metadata, reader }: SourceInput<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut offset = 0u64;
    let mut seen = 0usize;
    decode_ordered(
        budget,
        metadata.cancel,
        || loop {
            let (bytes, consumed) = super::bounded_line(
                &mut reader,
                metadata.cancel,
                super::MAX_SOURCE_BYTES.saturating_sub(offset),
            )?;
            if consumed == 0 {
                return Ok(None);
            }
            if seen >= super::MAX_RECORDS {
                return Err(super::policy_error("ECS source exceeds record limit"));
            }
            seen += 1;
            let current = offset;
            offset = offset.checked_add(consumed).ok_or_else(invalid)?;
            if consumed <= super::MAX_RECORD_BYTES as u64
                && bytes.iter().all(u8::is_ascii_whitespace)
            {
                continue;
            }
            let weight = bytes.len().saturating_mul(64);
            return Ok(Some(((bytes, current), weight)));
        },
        |(bytes, current)| {
            let parsed = if bytes.len() > super::MAX_RECORD_BYTES {
                Err(invalid())
            } else {
                prepare(&bytes, metadata.time_context)
            };
            (bytes, current, parsed)
        },
        |(bytes, current, parsed)| {
            match parsed.and_then(|(fields, time)| {
                materialize(fields, time, metadata, report.accepted as u64, current)
            }) {
                Ok(record) => {
                    let location =
                        ParserLocation::new(metadata.source.reference(), "parser-ecs", current)
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
                Err(_) => super::reject(&mut report, &bytes),
            }
            Ok(())
        },
    )?;
    Ok(report)
}

fn prepare(
    bytes: &[u8],
    context: Option<&irmind_app::ParserTimeContext>,
) -> Result<(SourceValue, IndexedTime), AppError> {
    let fields = decode_json_fields(bytes, SourceJsonLimits::default()).map_err(|_| invalid())?;
    let at = fields
        .field("@timestamp")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    if nested(&fields, "ecs", "version")
        .or_else(|| fields.field("ecs.version"))
        .is_none()
        && nested(&fields, "event", "kind")
            .or_else(|| fields.field("event.kind"))
            .is_none()
    {
        return Err(invalid());
    }
    let timestamp = timestamp(at, context)?;
    Ok((fields, timestamp))
}

fn materialize(
    fields: SourceValue,
    timestamp: IndexedTime,
    metadata: irmind_app::source_mapping::SourceMetadata<'_>,
    record: u64,
    offset: u64,
) -> Result<SourceRecordV1, AppError> {
    SourceRecordV1::try_from_source(
        EventOrigin::try_new(
            EvidenceHash::from_bytes(metadata.evidence_hash),
            record,
            Some(offset),
            "parser-ecs",
            "ecs-source-v1",
        )
        .map_err(|_| invalid())?,
        metadata.source.clone(),
        Some(timestamp),
        SourceFormatV1::try_new("ecs", "ecs-source-v1", BTreeMap::new()).map_err(|_| invalid())?,
        fields,
        DecodeAnnotationsV1::default(),
    )
    .map_err(|_| invalid())
}
fn nested<'a>(fields: &'a SourceValue, parent: &str, key: &str) -> Option<&'a SourceValue> {
    fields.field(parent)?.field(key)
}
fn timestamp(
    raw: &str,
    context: Option<&irmind_app::ParserTimeContext>,
) -> Result<IndexedTime, AppError> {
    if let Ok(time) = IndexedTime::from_rfc3339(raw, false) {
        return Ok(time);
    }
    let offset = context.ok_or_else(invalid)?.offset_minutes();
    let declared = format!(
        "{raw}{}{:02}:{:02}",
        if offset < 0 { '-' } else { '+' },
        offset.abs() / 60,
        offset.abs() % 60
    );
    IndexedTime::from_rfc3339(&declared, true).map_err(|_| invalid())
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}

pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        SourceDecoderSelection::new(Arc::new(EcsSourceDecoder))
            .with_detector(|source, sample| super::EcsParser.detect(source, sample))
            .with_time_detector(|source, sample| {
                super::EcsParser.time_context_requirement(source, sample)
            }),
    )
}
