use super::{
    AppError, CancellationToken, CaseId, GraphQueryFilter, Instant, MAX_NEIGHBOR_RECORDS,
    ParquetArtifactV1, ParquetStore, Predicate, ScanFlow, ScanSpec, ScanStatus, number, text,
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
    artifacts: &[ParquetArtifactV1],
    filter: &GraphQueryFilter,
) -> bool {
    let sources = |schema: &str| {
        artifacts
            .iter()
            .filter(|artifact| {
                artifact.schema_version == schema
                    && crate::parquet_store::scan::partition_matches(artifact, filter)
            })
            .flat_map(|artifact| {
                artifact.source_hashes.iter().map(|hash| {
                    (
                        &artifact.partition_date,
                        &artifact.partition_account,
                        &artifact.partition_region,
                        hash,
                    )
                })
            })
            .collect::<BTreeSet<_>>()
    };
    let entities = sources("irmind-entities-v2");
    !entities.is_empty()
        && !artifacts.iter().any(|artifact| {
            artifact.schema_version == "irmind-entities-v1"
                && crate::parquet_store::scan::partition_matches(artifact, filter)
        })
        && entities == sources("irmind-coobservations-v1")
}

impl ParquetStore {
    pub(super) fn scan_coobservations(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
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
                    for peer in peers {
                        if peer.0 == entity.0 && peer.1 == entity.1 {
                            continue;
                        }
                        let entry = neighbors.entry(peer).or_insert_with(|| (0, source.clone()));
                        entry.0 += 1;
                        if source < entry.1 {
                            entry.1.clone_from(&source);
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
