use super::{AppError, SourceMetadata, SourceRecordV1, VERSION, invalid};
use irmind_app::source_mapping::{
    DecodeAnnotationsV1, SourceFormatV1, SourceValue,
    json::{SourceJsonLimits, decode_json_fields},
};
use irmind_domain::{
    EventOrigin, EvidenceHash, IndexedInstant, IndexedTime, SourceDiscriminator, SourceMemberV1,
    TimePrecision,
};
use std::collections::BTreeMap;
pub(super) fn decode(
    bytes: &[u8],
    meta: SourceMetadata<'_>,
    accepted: u64,
    ordinal: u64,
    offset: Option<u64>,
    encoding: &str,
) -> Result<SourceRecordV1, AppError> {
    let fields = decode_json_fields(bytes, SourceJsonLimits::default()).map_err(|_| invalid())?;
    build(fields, meta, accepted, ordinal, offset, encoding)
}
pub(super) fn build(
    fields: SourceValue,
    meta: SourceMetadata<'_>,
    accepted: u64,
    ordinal: u64,
    offset: Option<u64>,
    encoding: &str,
) -> Result<SourceRecordV1, AppError> {
    let class = uint(&fields, "class_uid")?;
    uint(&fields, "category_uid")?;
    let version = fields
        .field("metadata")
        .and_then(|m| m.field("version"))
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    if !version.starts_with("1.") || version.len() > 64 {
        return Err(invalid());
    }
    let timestamp = timestamp(&fields)?;
    SourceRecordV1::try_from_source(
        EventOrigin::try_new(
            EvidenceHash::from_bytes(meta.evidence_hash),
            accepted,
            offset,
            "parser-ocsf",
            VERSION,
        )
        .map_err(|_| invalid())?,
        meta.source.clone(),
        Some(timestamp),
        SourceFormatV1::try_new(
            encoding,
            VERSION,
            BTreeMap::from([(SourceDiscriminator::RecordType, class.to_string())]),
        )
        .map_err(|_| invalid())?,
        fields,
        DecodeAnnotationsV1::try_new(false, vec![SourceMemberV1 { ordinal, offset }], None)
            .map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())
}
fn uint(fields: &SourceValue, key: &str) -> Result<u32, AppError> {
    match fields.field(key) {
        Some(SourceValue::Number(n)) => n.as_str().parse().map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}
fn timestamp(fields: &SourceValue) -> Result<IndexedTime, AppError> {
    let millis = match fields.field("time") {
        Some(SourceValue::Number(n)) => Some(n.as_str().parse::<i64>().map_err(|_| invalid())?),
        Some(SourceValue::Null) | None => None,
        _ => return Err(invalid()),
    };
    if let Some(value) = fields.field("time_dt") {
        let raw = value.as_text().ok_or_else(invalid)?;
        let parsed = IndexedTime::from_rfc3339(raw, false).map_err(|_| invalid())?;
        if millis.is_some_and(|m| parsed.instant().unix_micros().div_euclid(1000) != m) {
            return Err(invalid());
        }
        return Ok(parsed);
    }
    let micros = millis
        .ok_or_else(invalid)?
        .checked_mul(1000)
        .ok_or_else(invalid)?;
    IndexedTime::new(
        IndexedInstant::new(micros, 0).map_err(|_| invalid())?,
        TimePrecision::Millisecond,
        false,
    )
    .map_err(|_| invalid())
}
