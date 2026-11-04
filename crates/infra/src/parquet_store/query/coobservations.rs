use super::{
    AppError, CancellationToken, CaseId, GraphQueryFilter, Instant, MAX_NEIGHBOR_RECORDS,
    ParquetArtifact, Predicate, QueryStore, ScanFlow, ScanSpec, ScanStatus, number, text,
    time_rules,
};
use std::collections::{BTreeMap, BTreeSet};

type Entity = (String, String);

pub(super) struct CoobservationScan {
    pub neighbors: BTreeMap<Entity, (u64, String)>,
    pub sampled: bool,
    pub status: ScanStatus,
}

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
    let entities = sources("irmind-entities-v2");
    !entities.is_empty()
        && !artifacts.iter().any(|artifact| {
            artifact.schema_version() == "irmind-entities-v1"
                && crate::parquet_store::scan::partition_matches(artifact, filter)
        })
        && entities == sources("irmind-coobservations-v1")
}

impl QueryStore<'_> {
    pub(super) fn scan_coobservations(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CoobservationScan, AppError> {
        let mut rules = time_rules(filter);
        rules.extend([
            Predicate::Equal("entity_kind", entity.0.into()),
            Predicate::Equal("entity_value", entity.1.into()),
        ]);
        let mut neighbors = BTreeMap::<Entity, (u64, String)>::new();
        let mut selected_times = BTreeMap::<Entity, super::super::time_cell::TimeCell>::new();
        let mut count = 0;
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-coobservations-v1",
                columns: &["co_entities", "source_hash", "record_index"],
                predicates: &rules,
                deadline,
                cancel,
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    count += 1;
                    if count > MAX_NEIGHBOR_RECORDS {
                        return Ok(ScanFlow::Stop);
                    }
                    let source = format!(
                        "{}#{}",
                        text(batch, "source_hash", row)?,
                        number(batch, "record_index", row)?
                    );
                    let peers: Vec<Entity> = serde_json::from_str(text(batch, "co_entities", row)?)
                        .map_err(crate::parquet_store::storage)?;
                    let time = super::super::time_cell::TimeCell::from_batch(batch, row)?;
                    for peer in peers {
                        if peer.0 == entity.0 && peer.1 == entity.1 {
                            continue;
                        }
                        let entry = neighbors
                            .entry(peer.clone())
                            .or_insert_with(|| (0, source.clone()));
                        entry.0 += 1;
                        if selected_times
                            .get(&peer)
                            .map(|old| time.compare(old, false))
                            .transpose()?
                            .is_none_or(std::cmp::Ordering::is_lt)
                        {
                            entry.1.clone_from(&source);
                            selected_times.insert(peer, time.clone());
                        }
                    }
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        Ok(CoobservationScan {
            neighbors,
            sampled: count > MAX_NEIGHBOR_RECORDS,
            status,
        })
    }
}
