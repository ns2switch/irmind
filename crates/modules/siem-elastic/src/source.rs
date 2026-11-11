//! Decode response framing only. ECS interpretation remains in the ECS mapping module.
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceInput,
        json::{SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{
    DecodeAnnotationsV1, EventOrigin, EvidenceHash, IndexedTime, Provenance, SourceFormatV1,
    SourceMemberV1, SourceRecordV1, SourceValue, Tainted,
};
use std::{collections::BTreeMap, io::Read as _};
pub struct ElasticSourceDecoder;
impl SourceDecoder for ElasticSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "siem-elastic",
            version: "elastic-source-v1",
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
        let mut bytes = Vec::new();
        input
            .reader
            .take(5_000_001)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if bytes.len() > 5_000_000 {
            return Err(invalid());
        }
        let fields =
            decode_json_fields(&bytes, SourceJsonLimits::default()).map_err(|_| invalid())?;
        let Some(SourceValue::Array(hits)) = fields.field("hits").and_then(|v| v.field("hits"))
        else {
            // Aggregations remain signed tool results; buckets are not source events.
            if fields.field("aggregations").is_some() {
                return Ok(ParseReport {
                    accepted: 0,
                    rejected: 0,
                    samples: vec![],
                });
            }
            return Err(invalid());
        };
        if hits.len() > 20 {
            return Err(invalid());
        }
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: vec![],
        };
        for (ordinal, hit) in hits.iter().enumerate() {
            if input.metadata.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            match record(
                hit.clone(),
                report.accepted as u64,
                ordinal as u64,
                input.metadata,
            ) {
                Ok(record) => {
                    emit(record)?;
                    report.accepted += 1;
                }
                Err(_) => {
                    report.rejected += 1;
                }
            }
        }
        Ok(report)
    }
}
fn record(
    fields: SourceValue,
    index: u64,
    ordinal: u64,
    metadata: irmind_app::source_mapping::SourceMetadata<'_>,
) -> Result<Tainted<SourceRecordV1>, AppError> {
    let data = fields
        .field("_source")
        .or_else(|| fields.field("fields"))
        .ok_or_else(invalid)?;
    let timestamp = data
        .field("@timestamp")
        .and_then(|v| match v {
            SourceValue::Array(v) if v.len() == 1 => v[0].as_text(),
            _ => v.as_text(),
        })
        .ok_or_else(invalid)?;
    let time = IndexedTime::from_rfc3339(timestamp, false).map_err(|_| invalid())?;
    let origin = EventOrigin::try_new(
        EvidenceHash::from_bytes(metadata.evidence_hash),
        index,
        None,
        "siem-elastic",
        "elastic-source-v1",
    )
    .map_err(|_| invalid())?;
    let format = SourceFormatV1::try_new("elastic-search", "elastic-source-v1", BTreeMap::new())
        .map_err(|_| invalid())?;
    let annotations = DecodeAnnotationsV1::try_new(
        false,
        vec![SourceMemberV1 {
            ordinal,
            offset: None,
        }],
        None,
    )
    .map_err(|_| invalid())?;
    let record = SourceRecordV1::try_from_source(
        origin,
        metadata.source.clone(),
        Some(time),
        format,
        fields,
        annotations,
    )
    .map_err(|_| invalid())?;
    Ok(Tainted::from_external(
        record,
        Provenance::new(metadata.evidence_hash, Some(index), metadata.source.kind()),
    ))
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
