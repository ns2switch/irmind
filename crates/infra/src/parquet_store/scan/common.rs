use super::Predicate;
use irmind_domain::{ArtifactSchemaV2, GraphQueryFilter, ParquetArtifact};
pub(super) fn supported(artifact: &ParquetArtifact) -> bool {
    artifact
        .precise_metadata()
        .is_some_and(|v| v.schema.is_common())
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
    if artifact
        .precise_metadata()
        .is_some_and(|v| v.schema == ArtifactSchemaV2::CommonEvents)
    {
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
