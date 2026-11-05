use super::{AppError, ParquetArtifact, RecordBatch, invalid_source, storage};
use arrow::{
    array::{Array, ArrayRef, StringArray, UInt64Array},
    datatypes::{DataType, Field, Schema, TimeUnit},
};
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn same_family(actual: &str, requested: &str) -> bool {
    fn family(value: &str) -> Option<u8> {
        match value {
            "irmind-events-v2" | "irmind-events-v3" => Some(0),
            "irmind-entities-v1" | "irmind-entities-v2" | "irmind-entities-v3" => Some(1),
            "irmind-coobservations-v1" | "irmind-coobservations-v2" => Some(2),
            _ => None,
        }
    }
    family(actual).is_some() && family(actual) == family(requested)
}

pub(super) fn expected_type(name: &str, precise: bool) -> DataType {
    match name {
        "record_index" | "source_offset" => DataType::UInt64,
        "submicro_nanos" => DataType::UInt16,
        "time_precision" => DataType::UInt8,
        "time_inferred" => DataType::Boolean,
        "event_time" if precise => DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
        _ => DataType::Utf8,
    }
}

pub(super) fn validate_schema(artifact: &ParquetArtifact, schema: &Schema) -> Result<(), AppError> {
    if let ParquetArtifact::V2(v) = artifact {
        if !super::partitioning::supported_builder(&v.builder_version)
            || (v.builder_version == super::writer::precise::BUILDER
                && (!v.partition.scopes.is_empty() || v.partition.all_scope_overflow))
        {
            return Err(invalid_source());
        }
        let mut names = vec![
            "source_hash",
            "record_index",
            "event_time",
            "submicro_nanos",
            "time_precision",
            "time_inferred",
            "source_offset",
            "scope_account",
            "scope_region",
            "scope_host",
        ];
        match v.schema {
            irmind_domain::ArtifactSchemaV2::Events => {
                names.extend(["event", "text", "entities", "relations"]);
            }
            irmind_domain::ArtifactSchemaV2::Entities => {
                names.extend(["event", "entity_kind", "entity_value"]);
            }
            irmind_domain::ArtifactSchemaV2::Coobservations => {
                names.extend(["entity_kind", "entity_value", "co_entities"]);
            }
        }
        if names.len() != schema.fields().len() {
            return Err(invalid_source());
        }
        for name in names {
            let field = schema.field_with_name(name).map_err(storage)?;
            if field.data_type() != &expected_type(name, true)
                || field.is_nullable()
                    != matches!(name, "event_time" | "submicro_nanos" | "source_offset")
            {
                return Err(invalid_source());
            }
        }
    }
    Ok(())
}

pub(super) fn normalize_batch(
    batch: &RecordBatch,
    artifact: &ParquetArtifact,
    names: &BTreeMap<String, String>,
    display_time: bool,
) -> Result<RecordBatch, AppError> {
    let precise = matches!(artifact, ParquetArtifact::V2(_));
    let hashes = batch
        .column_by_name("source_hash")
        .and_then(|a| a.as_any().downcast_ref::<StringArray>())
        .ok_or_else(invalid_source)?;
    let indexes = batch
        .column_by_name("record_index")
        .and_then(|a| a.as_any().downcast_ref::<UInt64Array>())
        .ok_or_else(invalid_source)?;
    let mut source_names = Vec::with_capacity(batch.num_rows());
    let mut displayed = Vec::with_capacity(batch.num_rows());
    for row in 0..batch.num_rows() {
        if hashes.is_null(row)
            || indexes.is_null(row)
            || artifact
                .source_hashes()
                .binary_search_by(|h| h.as_str().cmp(hashes.value(row)))
                .is_err()
        {
            return Err(invalid_source());
        }
        let hash = hashes.value(row);
        if precise && !names.contains_key(hash) {
            return Err(invalid_source());
        }
        source_names.push(names.get(hash).map_or(hash, String::as_str));
        if precise && display_time {
            displayed.push(
                super::time_cell::read_time(batch, row)?
                    .map_or_else(String::new, irmind_app::IndexedTime::to_rfc3339),
            );
        }
    }
    let mut columns = batch
        .schema()
        .fields()
        .iter()
        .zip(batch.columns())
        .map(|(f, a)| (f.name().clone(), a.clone()))
        .collect::<Vec<_>>();
    if precise {
        let pos = columns
            .iter()
            .position(|(n, _)| n == "event_time")
            .ok_or_else(invalid_source)?;
        columns[pos].0 = "_irmind_instant".into();
        if display_time {
            columns.push((
                "event_time".into(),
                Arc::new(StringArray::from(displayed)) as ArrayRef,
            ));
        }
    }
    columns.push((
        "_irmind_source".into(),
        Arc::new(StringArray::from(source_names)) as ArrayRef,
    ));
    let schema = Schema::new(
        columns
            .iter()
            .map(|(name, a)| Field::new(name, a.data_type().clone(), a.null_count() > 0))
            .collect::<Vec<_>>(),
    );
    RecordBatch::try_new(
        Arc::new(schema),
        columns.into_iter().map(|(_, a)| a).collect(),
    )
    .map_err(storage)
}
