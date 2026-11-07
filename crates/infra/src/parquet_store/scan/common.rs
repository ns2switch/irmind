use super::Predicate;
use irmind_domain::{ArtifactSchemaV2, GraphQueryFilter, ParquetArtifact};
pub(super) fn supported(artifact: &ParquetArtifact) -> bool {
    matches!(artifact,ParquetArtifact::V2(value) if value.schema.is_common())
}
pub(super) fn rules(artifact: &ParquetArtifact, filter: &GraphQueryFilter) -> Vec<Predicate> {
    if !supported(artifact) {
        return Vec::new();
    }
    let selected = filter.common();
    let mut rules = vec![
        Predicate::Mask(
            "event_category_bits",
            selected.category.map_or(0, |v| 1u32 << v.code()),
            0x000f_ffff,
        ),
        Predicate::Mask(
            "event_type_bits",
            selected.event_type.map_or(0, |v| 1u32 << v.code()),
            0x0003_ffff,
        ),
        Predicate::SmallEqual(
            "event_outcome",
            selected.outcome.map(irmind_domain::EventOutcome::code),
            2,
        ),
        Predicate::SmallEqual("event_kind", None, 2),
    ];
    if matches!(artifact,ParquetArtifact::V2(v) if v.schema==ArtifactSchemaV2::CommonEvents) {
        rules.push(Predicate::Mask(
            "event_role_bits",
            selected.role.map_or(0, |role| 1u32 << role.code()),
            0x01fe,
        ));
    } else {
        rules.push(Predicate::SmallEqual(
            "entity_role",
            selected.role.map(irmind_domain::EntityRole::code),
            8,
        ));
    }
    rules
}

pub(super) const IDENTITY_COLUMNS: [&str; 4] = [
    "identity_scope",
    "entity_role",
    "entity_field",
    "co_observations",
];
pub(super) fn is_extra(name: &str) -> bool {
    IDENTITY_COLUMNS.contains(&name)
        || name == "common_payload"
        || name == "event_role_bits"
        || super::super::common_format::CLASS_COLUMNS.contains(&name)
}
pub(super) fn projection_defaults(
    batch: super::RecordBatch,
    spec: &super::ScanSpec<'_>,
    artifact: &ParquetArtifact,
) -> Result<super::RecordBatch, super::AppError> {
    use arrow::{
        array::{ArrayRef, StringArray, UInt8Array, UInt16Array},
        datatypes::{Field, Schema},
    };
    use std::sync::Arc;
    if supported(artifact) || !spec.columns.contains(&"identity_scope") {
        return Ok(batch);
    }
    let count = batch.num_rows();
    let mut fields = batch.schema().fields().iter().cloned().collect::<Vec<_>>();
    let mut columns = batch.columns().to_vec();
    for (name, array) in [
        (
            "identity_scope",
            Arc::new(StringArray::from(vec!["legacy-unspecified"; count])) as ArrayRef,
        ),
        (
            "entity_role",
            Arc::new(UInt8Array::from(vec![0; count])) as ArrayRef,
        ),
        (
            "entity_field",
            Arc::new(UInt16Array::from(vec![0; count])) as ArrayRef,
        ),
    ] {
        fields.push(Arc::new(Field::new(name, array.data_type().clone(), false)));
        columns.push(array);
    }
    super::RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).map_err(super::storage)
}
