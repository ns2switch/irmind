use super::{AppError, ParquetArtifact, RecordBatch, invalid_source, storage};
use arrow::{
    array::{Array, ArrayRef, StringArray, UInt64Array},
    datatypes::{DataType, Field, Schema, TimeUnit},
};
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn same_family(actual: &str, requested: &str) -> bool {
    fn family(value: &str) -> Option<u8> {
        match value {
            "irmind-events-v2" | "irmind-events-v3" | "irmind-events-v4" => Some(0),
            "irmind-entities-v1" | "irmind-entities-v2" | "irmind-entities-v3"
            | "irmind-entities-v4" => Some(1),
            "irmind-coobservations-v1"
            | "irmind-coobservations-v2"
            | "irmind-coobservations-v3" => Some(2),
            _ => None,
        }
    }
    family(actual).is_some() && family(actual) == family(requested)
}

pub(super) fn expected_type(name: &str, precise: bool) -> DataType {
    match name {
        "record_index" | "source_offset" => DataType::UInt64,
        "submicro_nanos" | "entity_field" | "event_role_bits" => DataType::UInt16,
        "event_category_bits" | "event_type_bits" => DataType::UInt32,
        "event_outcome" | "event_kind" | "entity_role" | "time_precision" => DataType::UInt8,
        "time_inferred" => DataType::Boolean,
        "event_time" if precise => DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
        _ => DataType::Utf8,
    }
}

pub(super) fn validate_schema(artifact: &ParquetArtifact, schema: &Schema) -> Result<(), AppError> {
    let ParquetArtifact::V3(mapped) = artifact else {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredCaseFormat,
        ));
    };
    let v = mapped.core();
    if !super::partitioning::supported_builder(&v.builder_version) {
        return Err(invalid_source());
    }
    super::common_format::validate_metadata(v.schema, schema, &v.builder_version)?;
    validate_columns(v.schema, schema)
}

pub(super) fn validate_row_count(artifact: &ParquetArtifact, rows: i64) -> Result<(), AppError> {
    if let ParquetArtifact::V3(mapped) = artifact
        && u64::try_from(rows).ok() != Some(mapped.pipeline().rows())
    {
        return Err(invalid_source());
    }
    Ok(())
}

pub(crate) fn validate_common_export_schema(
    id: irmind_domain::ArtifactSchemaV2,
    schema: &Schema,
) -> Result<(), AppError> {
    if !id.is_common() {
        return Err(invalid_source());
    }
    super::common_format::validate_metadata(id, schema, super::common_format::BUILDER)?;
    validate_columns(id, schema)
}

fn validate_columns(id: irmind_domain::ArtifactSchemaV2, schema: &Schema) -> Result<(), AppError> {
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
    match id {
        irmind_domain::ArtifactSchemaV2::Events | irmind_domain::ArtifactSchemaV2::CommonEvents => {
            names.extend(["event", "text", "entities", "relations"]);
        }
        irmind_domain::ArtifactSchemaV2::Entities
        | irmind_domain::ArtifactSchemaV2::CommonEntities => {
            names.extend(["event", "entity_kind", "entity_value"]);
        }
        irmind_domain::ArtifactSchemaV2::Coobservations
        | irmind_domain::ArtifactSchemaV2::CommonCoobservations => {
            names.extend(["entity_kind", "entity_value", "co_entities"]);
        }
    }
    names.extend(super::common_format::extra_columns(id));
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
    Ok(())
}

pub(super) fn normalize_batch(
    batch: &RecordBatch,
    artifact: &ParquetArtifact,
    names: &BTreeMap<String, String>,
    display_time: bool,
) -> Result<RecordBatch, AppError> {
    let precise = artifact.precise_metadata().is_some();
    let hashes = batch
        .column_by_name("source_hash")
        .and_then(|a| a.as_any().downcast_ref::<StringArray>())
        .ok_or_else(invalid_source)?;
    let indexes = batch
        .column_by_name("record_index")
        .and_then(|a| a.as_any().downcast_ref::<UInt64Array>())
        .ok_or_else(invalid_source)?;
    let mut source_names = Vec::with_capacity(batch.num_rows());
    let mut displayed = Vec::with_capacity(if precise && display_time {
        batch.num_rows()
    } else {
        0
    });
    let mut previous = None::<(&str, &str)>;
    for row in 0..batch.num_rows() {
        if hashes.is_null(row) || indexes.is_null(row) {
            return Err(invalid_source());
        }
        let hash = hashes.value(row);
        let source = if let Some((old, name)) = previous
            && old == hash
        {
            name
        } else {
            let name = source_name(hash, artifact, names, precise)?;
            previous = Some((hash, name));
            name
        };
        source_names.push(source);
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

fn source_name<'a>(
    hash: &'a str,
    artifact: &ParquetArtifact,
    names: &'a BTreeMap<String, String>,
    precise: bool,
) -> Result<&'a str, AppError> {
    if artifact
        .source_hashes()
        .binary_search_by(|h| h.as_str().cmp(hash))
        .is_err()
    {
        return Err(invalid_source());
    }
    let source = names.get(hash);
    if precise && source.is_none() {
        return Err(invalid_source());
    }
    Ok(source.map_or(hash, String::as_str))
}

#[cfg(test)]
mod tests;
