//! Prefer co-observations only when every selected entity source is covered.
use super::{GraphQueryFilter, ParquetArtifact};
use std::collections::BTreeSet;

pub(super) fn coobservation_available(
    artifacts: &[ParquetArtifact],
    filter: &GraphQueryFilter,
) -> bool {
    let sources = |schema: &str| {
        artifacts
            .iter()
            .filter(|artifact| {
                super::super::format::same_family(artifact.schema_version(), schema)
                    && crate::parquet_store::scan::partition_matches(artifact, filter)
            })
            .flat_map(|artifact| {
                artifact.source_hashes().iter().map(|hash| {
                    (
                        artifact.path().rsplit_once('/').map(|(parent, _)| parent),
                        artifact.parser_version(),
                        hash,
                    )
                })
            })
            .collect::<BTreeSet<_>>()
    };
    let entities = sources("irmind-entities-v4");
    !entities.is_empty() && entities == sources("irmind-coobservations-v3")
}
