use super::{SourceMetadata, SourceRecordV1, VERSION, invalid};
use irmind_app::{
    AppError, IndexedTime,
    source_mapping::{DecodeAnnotationsV1, SourceDiscriminator, SourceFormatV1, SourceValue},
};
use irmind_domain::{EventOrigin, EvidenceHash, IndexedInstant, SourceMemberV1, TimePrecision};
use std::collections::BTreeMap;
pub(super) struct Decoded {
    pub fields: SourceValue,
    pub timestamp: IndexedTime,
    pub dataset: String,
    pub partial: bool,
    pub members: Vec<SourceMemberV1>,
    pub offset: Option<u64>,
    pub raw: Option<String>,
}
impl Decoded {
    pub(super) fn into_source(
        self,
        meta: SourceMetadata<'_>,
        index: u64,
    ) -> Result<SourceRecordV1, AppError> {
        let format = SourceFormatV1::try_new(
            "linux",
            VERSION,
            BTreeMap::from([(SourceDiscriminator::Dataset, self.dataset)]),
        )
        .map_err(|_| invalid())?;
        let origin = EventOrigin::try_new(
            EvidenceHash::from_bytes(meta.evidence_hash),
            index,
            self.offset,
            "parser-linux",
            VERSION,
        )
        .map_err(|_| invalid())?;
        SourceRecordV1::try_from_source(
            origin,
            meta.source.clone(),
            Some(self.timestamp),
            format,
            self.fields,
            DecodeAnnotationsV1::try_new(self.partial, self.members, self.raw)
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())
    }
}
pub(super) fn object(fields: Vec<(&str, SourceValue)>) -> Result<SourceValue, AppError> {
    SourceValue::object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
        .map_err(|_| invalid())
}
pub(super) fn text(value: &str) -> SourceValue {
    SourceValue::Text(value.into())
}
pub(super) fn member(index: u64, offset: u64) -> SourceMemberV1 {
    SourceMemberV1 {
        ordinal: index,
        offset: Some(offset),
    }
}
pub(super) fn journal(line: &str, index: u64, offset: u64) -> Result<Decoded, AppError> {
    let fields = irmind_app::source_mapping::json::decode_json_fields(
        line.as_bytes(),
        irmind_app::source_mapping::json::SourceJsonLimits::default(),
    )
    .map_err(|_| invalid())?;
    let micros = fields
        .field("__REALTIME_TIMESTAMP")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    let timestamp = IndexedTime::new(
        IndexedInstant::new(micros, 0).map_err(|_| invalid())?,
        TimePrecision::Microsecond,
        false,
    )
    .map_err(|_| invalid())?;
    Ok(Decoded {
        fields,
        timestamp,
        dataset: "journald".into(),
        partial: false,
        members: vec![member(index, offset)],
        offset: Some(offset),
        raw: Some(line.into()),
    })
}
