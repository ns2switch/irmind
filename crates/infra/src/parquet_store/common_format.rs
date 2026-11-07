//! Physical schemas are bound by their signed IDs and checked file metadata.
use super::{AppError, invalid_source};
use arrow::datatypes::Schema;
use irmind_domain::{ArtifactSchemaV2, COMMON_EVENT_V1};

pub(super) const BUILDER: &str = irmind_domain::COMMON_EVENT_BUILDER;
pub(super) const CLASS_COLUMNS: [&str; 4] = [
    "event_category_bits",
    "event_type_bits",
    "event_outcome",
    "event_kind",
];

pub(super) fn extra_columns(schema: ArtifactSchemaV2) -> Vec<&'static str> {
    if !schema.is_common() {
        return Vec::new();
    }
    let mut columns = CLASS_COLUMNS.to_vec();
    match schema {
        ArtifactSchemaV2::CommonEvents => columns.extend(["common_payload", "event_role_bits"]),
        ArtifactSchemaV2::CommonEntities => {
            columns.extend(["entity_role", "entity_field", "identity_scope"]);
        }
        ArtifactSchemaV2::CommonCoobservations => columns.extend([
            "entity_role",
            "entity_field",
            "identity_scope",
            "co_observations",
        ]),
        _ => {}
    }
    columns
}
pub(super) fn validate_metadata(
    id: ArtifactSchemaV2,
    schema: &Schema,
    builder: &str,
) -> Result<(), AppError> {
    if id.is_common() {
        if builder != BUILDER
            || schema
                .metadata()
                .get("irmind.common.schema")
                .map(String::as_str)
                != Some(COMMON_EVENT_V1)
        {
            return Err(invalid_source());
        }
    } else if builder == BUILDER || schema.metadata().contains_key("irmind.common.schema") {
        return Err(invalid_source());
    }
    Ok(())
}
