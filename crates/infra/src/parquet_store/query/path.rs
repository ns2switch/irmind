use super::{
    AppError, CancellationToken, CaseId, GraphQueryFilter, Instant, ParquetArtifactV1,
    ParquetStore, QUERY_DEADLINE, ScanFlow, ScanSpec, ScanStatus, TargetScan,
    coobservation_available, number, text, time_rules,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

const MAX_PATH_EXPANSIONS: usize = 200;
const MAX_PATH_NEIGHBORS: usize = 50;
const MAX_PATH_HOPS: usize = 3;

type Entity = (String, String);
type Breadcrumbs = HashMap<Entity, (Entity, String)>;

pub(super) struct CandidateBatch {
    entries: Vec<(String, String, String)>,
    partial: bool,
}

impl ParquetStore {
    pub(crate) fn path_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        from: (&str, &str),
        to: (&str, &str),
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let start = (from.0.to_owned(), from.1.to_owned());
        let goal = (to.0.to_owned(), to.1.to_owned());
        if start == goal {
            return Ok(format!("{} {} is the same entity", from.0, from.1));
        }
        let deadline = Instant::now() + QUERY_DEADLINE;
        let mut queue = VecDeque::from([(start.clone(), 0usize)]);
        let mut visited = HashSet::from([start.clone()]);
        let mut previous = Breadcrumbs::new();
        let mut expanded = 0usize;
        let mut truncated = false;
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= MAX_PATH_HOPS {
                continue;
            }
            if expanded >= MAX_PATH_EXPANSIONS || Instant::now() >= deadline {
                truncated = true;
                break;
            }
            expanded += 1;
            let Some(batch) =
                self.path_candidates_native(id, artifacts, filter, &current, deadline, cancel)?
            else {
                truncated = true;
                break;
            };
            truncated |= batch.partial;
            for (kind, value, source) in batch.entries {
                let next = (kind, value);
                if !visited.insert(next.clone()) {
                    continue;
                }
                previous.insert(next.clone(), (current.clone(), source));
                if next == goal {
                    return format_path(&start, &goal, &previous);
                }
                queue.push_back((next, depth + 1));
            }
        }
        if truncated {
            Ok("no path found within 3 hops / 200 expanded entities / 50 neighbors per entity / 10 seconds; search was truncated".into())
        } else {
            Ok("no co-observation path found within 3 hops".into())
        }
    }

    fn path_candidates_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: &Entity,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Option<CandidateBatch>, AppError> {
        if coobservation_available(artifacts, filter) {
            let result = self.scan_coobservations(
                id,
                artifacts,
                filter,
                (&entity.0, &entity.1),
                deadline,
                cancel,
            )?;
            if result.status == ScanStatus::Deadline {
                return Ok(None);
            }
            let partial = result.sampled || result.neighbors.len() > MAX_PATH_NEIGHBORS;
            return Ok(Some(CandidateBatch {
                entries: result
                    .neighbors
                    .into_iter()
                    .take(MAX_PATH_NEIGHBORS)
                    .map(|((kind, value), (_, source))| (kind, value, source))
                    .collect(),
                partial,
            }));
        }
        self.path_candidates_legacy(id, artifacts, filter, entity, deadline, cancel)
    }

    fn path_candidates_legacy(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: &Entity,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Option<CandidateBatch>, AppError> {
        let TargetScan {
            records: targets,
            sampled,
            status,
        } = self.native_targets(
            id,
            artifacts,
            filter,
            (&entity.0, &entity.1),
            deadline,
            cancel,
        )?;
        if status == ScanStatus::Deadline {
            return Ok(None);
        }
        let mut neighbors = BTreeMap::<Entity, String>::new();
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-entities-v1",
                columns: &["source_hash", "record_index", "entity_kind", "entity_value"],
                predicates: &time_rules(filter),
                deadline,
                cancel,
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    let hash = text(batch, "source_hash", row)?;
                    let index = number(batch, "record_index", row)?;
                    if !targets
                        .get(hash)
                        .is_some_and(|indexes| indexes.contains(&index))
                    {
                        continue;
                    }
                    let kind = text(batch, "entity_kind", row)?;
                    let value = text(batch, "entity_value", row)?;
                    if (kind, value) == (&entity.0[..], &entity.1[..]) {
                        continue;
                    }
                    let source = format!("{hash}#{index}");
                    let current = neighbors
                        .entry((kind.into(), value.into()))
                        .or_insert_with(|| source.clone());
                    if source < *current {
                        *current = source;
                    }
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        if status == ScanStatus::Deadline {
            return Ok(None);
        }
        let partial = sampled || neighbors.len() > MAX_PATH_NEIGHBORS;
        Ok(Some(CandidateBatch {
            entries: neighbors
                .into_iter()
                .take(MAX_PATH_NEIGHBORS)
                .map(|((kind, value), source)| (kind, value, source))
                .collect(),
            partial,
        }))
    }
}

fn format_path(start: &Entity, goal: &Entity, previous: &Breadcrumbs) -> Result<String, AppError> {
    let mut steps = Vec::new();
    let mut cursor = goal.clone();
    while &cursor != start {
        let (parent, source) = previous
            .get(&cursor)
            .ok_or_else(|| AppError::Policy("incomplete Parquet path".into()))?;
        steps.push(format!(
            "{} {} --[co-observed in {source}]--> {} {}",
            parent.0, parent.1, cursor.0, cursor.1
        ));
        cursor = parent.clone();
    }
    steps.reverse();
    Ok(steps.join("\n"))
}
