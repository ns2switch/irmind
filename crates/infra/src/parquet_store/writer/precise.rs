#[cfg(test)]
use super::row::{first_string, raw_host};
use super::{
    AppError, Arc, ArrayRef, ArtifactSink, EvidenceHash, RecordBatch, RecordRow, StringArray,
    UInt64Array, invalid_source, storage,
};
use arrow::array::{BooleanArray, TimestampMicrosecondArray, UInt8Array, UInt16Array};
use arrow::datatypes::Schema;
use irmind_domain::{ARTIFACT_V2_STABLE_ORDER, ARTIFACT_V2_TIME_SEMANTICS, ParquetArtifactV2};

#[cfg(test)]
impl RecordRow {
    pub(in crate::parquet_store) fn from_partitioned(
        indexed: &irmind_app::IndexedGraphRecord,
        hash: &EvidenceHash,
    ) -> Result<Self, AppError> {
        Self::indexed_row(indexed, hash, true, true)
    }

    fn indexed_row(
        indexed: &irmind_app::IndexedGraphRecord,
        hash: &EvidenceHash,
        precise: bool,
        generic: bool,
    ) -> Result<Self, AppError> {
        let mut row = Self::from_record(&indexed.record, hash)?;
        if precise {
            row.precise = true;
            row.time = indexed.time;
            row.source_offset = indexed.source_offset;
            row.partition.account.clear();
            row.partition.region.clear();
            row.at = indexed
                .time
                .map_or_else(String::new, irmind_app::IndexedTime::to_rfc3339);
            row.partition.date = indexed
                .time
                .map_or_else(|| "unknown".into(), |t| t.instant().utc_date());
            let value: serde_json::Value =
                serde_json::from_str(&indexed.record.text).map_err(storage)?;
            if generic {
                row.scope_region = first_string(
                    &value,
                    &[
                        "/awsRegion",
                        "/region",
                        "/resource/labels/location",
                        "/location",
                        "/provider",
                    ],
                )
                .into();
            }
            row.scope_host = if generic {
                raw_host(&value)
            } else {
                first_string(
                    &value,
                    &[
                        "/host",
                        "/hostname",
                        "/hostName",
                        "/event/host",
                        "/Computer",
                        "/Host",
                        "/_Source",
                    ],
                )
            }
            .into();
        }
        Ok(row)
    }
}

pub(super) fn columns(
    batch: &RecordBatch,
    rows: &[RecordRow],
    indexes: &[usize],
) -> Result<RecordBatch, AppError> {
    let selected = indexes.iter().map(|i| &rows[*i]).collect::<Vec<_>>();
    let times = TimestampMicrosecondArray::from(
        selected
            .iter()
            .map(|r| r.time.map(|t| t.instant().unix_micros()))
            .collect::<Vec<_>>(),
    )
    .with_timezone("UTC");
    let mut columns = batch
        .schema()
        .fields()
        .iter()
        .zip(batch.columns())
        .map(|(f, a)| (f.name().clone(), a.clone()))
        .collect::<Vec<_>>();
    let slot = columns
        .iter()
        .position(|(name, _)| name == "event_time")
        .ok_or_else(invalid_source)?;
    columns[slot].1 = Arc::new(times);
    columns.extend(metadata_columns(&selected));
    let fields = columns
        .iter()
        .map(|(name, a)| {
            arrow::datatypes::Field::new(
                name,
                a.data_type().clone(),
                matches!(
                    name.as_str(),
                    "event_time" | "submicro_nanos" | "source_offset"
                ),
            )
        })
        .collect::<Vec<_>>();
    RecordBatch::try_new(
        Arc::new(Schema::new(fields)),
        columns.into_iter().map(|(_, a)| a).collect(),
    )
    .map_err(storage)
}

fn metadata_columns(selected: &[&RecordRow]) -> Vec<(String, ArrayRef)> {
    vec![
        (
            "submicro_nanos".into(),
            Arc::new(UInt16Array::from(
                selected
                    .iter()
                    .map(|r| r.time.map(|t| t.instant().submicro_nanos()))
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "time_precision".into(),
            Arc::new(UInt8Array::from(
                selected
                    .iter()
                    .map(|r| r.time.map_or(0, |t| t.precision().code()))
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "time_inferred".into(),
            Arc::new(BooleanArray::from(
                selected
                    .iter()
                    .map(|r| r.time.is_some_and(irmind_app::IndexedTime::inferred))
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "source_offset".into(),
            Arc::new(UInt64Array::from(
                selected.iter().map(|r| r.source_offset).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "scope_account".into(),
            Arc::new(StringArray::from(
                selected
                    .iter()
                    .map(|r| r.scope_account.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "scope_region".into(),
            Arc::new(StringArray::from(
                selected
                    .iter()
                    .map(|r| r.scope_region.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            "scope_host".into(),
            Arc::new(StringArray::from(
                selected
                    .iter()
                    .map(|r| r.scope_host.as_str())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
    ]
}

pub(super) fn manifest(
    sink: &ArtifactSink,
    hash: &EvidenceHash,
    parser: irmind_app::ParserIdentity<'_>,
    size: u64,
    digest: &[u8; 32],
) -> Result<ParquetArtifactV2, AppError> {
    Ok(ParquetArtifactV2 {
        path: sink.relative_path.clone(),
        size,
        sha256: EvidenceHash::from_bytes(*digest),
        parser_id: parser.name.into(),
        parser_version: parser.version.into(),
        schema: sink.kind.schema(),
        partition: sink.partition.scope.clone().ok_or_else(invalid_source)?,
        source_hashes: vec![hash.clone()],
        time_semantics: ARTIFACT_V2_TIME_SEMANTICS.into(),
        stable_order: ARTIFACT_V2_STABLE_ORDER.into(),
        builder_version: irmind_domain::COMMON_EVENT_DIRECT_BUILDER.into(),
        superseded_hashes: Vec::new(),
    })
}
