//! Original helper fields and measured offsets; classification belongs to mappings.
use super::{EvtxParser, bad, codec};
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder, SourceParallelism,
    source_mapping::{SourceFileInput, SourceInput, SourceMetadata},
};
use irmind_domain::{
    DecodeAnnotationsV1, EventOrigin, EvidenceHash, IndexedTime, ParserLocation, Provenance,
    SourceDiscriminator, SourceFormatV1, SourceMemberV1, SourceNumber, SourceRecordV1, SourceValue,
    Tainted,
};
use std::collections::BTreeMap;

pub const SOURCE_VERSION: &str = "evtx-source-v1";
impl SourceDecoder for EvtxParser {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-evtx",
            version: SOURCE_VERSION,
        }
    }
    fn source_parallelism(&self) -> SourceParallelism {
        if cfg!(windows) {
            SourceParallelism::Serial
        } else {
            SourceParallelism::Concurrent
        }
    }
    fn needs_random_access(&self, _: &str, sample: &[u8]) -> bool {
        codec::detect(sample)
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        _: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        Err(bad(
            "EVTX requires an authenticated seekable file; remote objects use the private case spool",
        ))
    }
    fn decode_local_file(
        &self,
        input: SourceFileInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_with_budget(
            irmind_app::source_mapping::DecodeInput::File(input),
            irmind_app::source_mapping::DecodeBudget::sequential(),
            emit,
        )
    }
    fn decode_with_budget(
        &self,
        input: irmind_app::source_mapping::DecodeInput<'_>,
        budget: irmind_app::source_mapping::DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let irmind_app::source_mapping::DecodeInput::File(input) = input else {
            return self.decode_reader(input.into_reader(), emit);
        };
        let workers = budget
            .workers()
            .min((budget.queued_bytes() / (32 * 1024 * 1024)).max(1))
            .min(64);
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let size = input.file.metadata().map_err(|_| invalid())?.len();
        let mut state = codec::State::new(size);
        let result = self
            .decode_file_workers(input.file, input.metadata.cancel, workers, &mut |bytes| {
                state.project_frame(bytes, &mut |row| {
                    let Ok(record) = decode(row, input.metadata) else {
                        return Ok(false);
                    };
                    emit(record)?;
                    Ok(true)
                })
            })
            .and_then(|()| state.finish());
        self.completed(result)
    }
}
fn decode(
    row: codec::DecodedRecord,
    metadata: SourceMetadata<'_>,
) -> Result<Tainted<SourceRecordV1>, AppError> {
    let timestamp = IndexedTime::from_rfc3339(&row.timestamp, false).map_err(|_| invalid())?;
    if timestamp.instant().submicro_nanos() % 100 != 0 {
        return Err(invalid());
    }
    let fields = value(row.event, 0, &mut 0)?;
    let format = format(&fields)?;
    let record = SourceRecordV1::try_from_source(
        EventOrigin::try_new(
            EvidenceHash::from_bytes(metadata.evidence_hash),
            row.accepted_index,
            Some(row.offset),
            "parser-evtx",
            SOURCE_VERSION,
        )
        .map_err(|_| invalid())?,
        metadata.source.clone(),
        Some(timestamp),
        format,
        fields,
        DecodeAnnotationsV1::try_new(
            false,
            vec![SourceMemberV1 {
                ordinal: row.record_id,
                offset: Some(row.offset),
            }],
            None,
        )
        .map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    let location = ParserLocation::new(metadata.source.reference(), "parser-evtx", row.offset)
        .map_err(|_| invalid())?;
    Ok(Tainted::from_external(
        record,
        Provenance::new(
            metadata.evidence_hash,
            Some(row.accepted_index),
            metadata.source.kind(),
        )
        .with_parser_location(location),
    ))
}
fn format(fields: &SourceValue) -> Result<SourceFormatV1, AppError> {
    let system = fields
        .field("Event")
        .and_then(|v| v.field("System"))
        .ok_or_else(invalid)?;
    let mut discriminators = BTreeMap::new();
    for (kind, value) in [
        (SourceDiscriminator::Channel, system.field("Channel")),
        (
            SourceDiscriminator::Provider,
            system
                .field("Provider")
                .and_then(|v| v.field("#attributes"))
                .and_then(|v| v.field("Name")),
        ),
    ] {
        if let Some(SourceValue::Text(text)) = value {
            discriminators.insert(kind, text.clone());
        }
    }
    let id_field = system.field("EventID");
    let id_field = id_field.and_then(|value| value.field("#text").or(Some(value)));
    let id = match id_field {
        Some(SourceValue::Text(id)) => Some(id.clone()),
        Some(SourceValue::Number(id)) => Some(id.as_str().to_owned()),
        _ => None,
    };
    if let Some(id) = id {
        discriminators.insert(SourceDiscriminator::RecordType, id);
    }
    SourceFormatV1::try_new("evtx", SOURCE_VERSION, discriminators).map_err(|_| invalid())
}
fn value(raw: serde_json::Value, depth: usize, nodes: &mut usize) -> Result<SourceValue, AppError> {
    *nodes += 1;
    if depth > irmind_domain::SOURCE_MAX_DEPTH || *nodes > irmind_domain::SOURCE_MAX_NODES {
        return Err(invalid());
    }
    Ok(match raw {
        serde_json::Value::Null => SourceValue::Null,
        serde_json::Value::Bool(v) => SourceValue::Boolean(v),
        serde_json::Value::Number(v) => {
            SourceValue::Number(SourceNumber::try_new(&v.to_string()).map_err(|_| invalid())?)
        }
        serde_json::Value::String(v) => SourceValue::Text(v),
        serde_json::Value::Array(v) => SourceValue::Array(
            v.into_iter()
                .map(|v| value(v, depth + 1, nodes))
                .collect::<Result<_, _>>()?,
        ),
        serde_json::Value::Object(v) => SourceValue::Object(
            v.into_iter()
                .map(|(k, v)| Ok((k, value(v, depth + 1, nodes)?)))
                .collect::<Result<_, AppError>>()?,
        ),
    })
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}

pub fn detect_source(_: &str, sample: &[u8]) -> Option<irmind_app::ParserConfidence> {
    codec::detect(sample)
        .then(|| irmind_app::ParserConfidence::new(95).ok())
        .flatten()
}
#[cfg(feature = "fuzzing")]
pub(super) fn fuzz(bytes: &[u8]) {
    let Ok(source) = irmind_domain::SourceReferenceV1::file("synthetic.evtx") else {
        return;
    };
    let cancel = irmind_app::CancellationToken::new();
    let metadata = SourceMetadata {
        source: &source,
        evidence_hash: [0; 32],
        time_context: None,
        cluster_context: None,
        cancel: &cancel,
    };
    let mut state = codec::State::new(69632);
    for line in bytes.split(|byte| *byte == b'\n').take(128) {
        let _ = state.project_frame(line, &mut |row| Ok(decode(row, metadata).is_ok()));
    }
    let _ = state.finish();
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
