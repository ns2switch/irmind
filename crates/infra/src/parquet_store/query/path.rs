use super::{
    AppError, CancellationToken, CaseId, MAX_NEIGHBOR_RECORDS, ParquetArtifactV1, ParquetStore,
    QUERY_DEADLINE,
};
use irmind_domain::GraphQueryFilter;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

const MAX_PATH_EXPANSIONS: usize = 200;
const MAX_PATH_NEIGHBORS: usize = 50;
const MAX_PATH_HOPS: usize = 3;

type Entity = (String, String);
type Breadcrumbs = HashMap<Entity, (Entity, String)>;
type PathCandidate = (String, String, String);

struct CandidateBatch {
    entries: Vec<PathCandidate>,
    partial: bool,
}

impl ParquetStore {
    pub(crate) fn path_artifacts(
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
        let begun = Instant::now();
        let mut queue = VecDeque::from([(start.clone(), 0usize)]);
        let mut visited = HashSet::from([start.clone()]);
        let mut previous = Breadcrumbs::new();
        let mut expanded = 0usize;
        let mut truncated = false;
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= MAX_PATH_HOPS {
                continue;
            }
            if expanded >= MAX_PATH_EXPANSIONS || begun.elapsed() >= QUERY_DEADLINE {
                truncated = true;
                break;
            }
            expanded += 1;
            let remaining = QUERY_DEADLINE.saturating_sub(begun.elapsed());
            let batch = self.path_candidates(id, artifacts, filter, &current, remaining, cancel)?;
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

    fn path_candidates(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: &Entity,
        remaining: Duration,
        cancel: &CancellationToken,
    ) -> Result<CandidateBatch, AppError> {
        let target_limit = (MAX_NEIGHBOR_RECORDS + 1).to_string();
        let sample_limit = MAX_NEIGHBOR_RECORDS.to_string();
        let candidate_limit = (MAX_PATH_NEIGHBORS + 1).to_string();
        let rows = self.query_rows_limited(id, artifacts, filter,
            ("WITH records AS NOT MATERIALIZED (SELECT * FROM {entities}), targets AS MATERIALIZED (SELECT source_hash,record_index FROM records WHERE entity_kind=? AND entity_value=? LIMIT CAST(? AS BIGINT)), bounded AS (SELECT source_hash,record_index FROM targets LIMIT CAST(? AS BIGINT)) SELECT n.entity_kind,n.entity_value,MIN(n.source_hash || '#' || CAST(n.record_index AS VARCHAR)),(SELECT COUNT(*) FROM targets)>CAST(? AS BIGINT) FROM records n JOIN bounded USING (source_hash,record_index) WHERE (n.entity_kind<>? OR n.entity_value<>?) GROUP BY 1,2 ORDER BY 1,2 LIMIT CAST(? AS BIGINT)", &[&entity.0,&entity.1,&target_limit,&sample_limit,&sample_limit,&entity.0,&entity.1,&candidate_limit], remaining), cancel,
            |row| Ok((row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, String>(2)?,row.get::<_, bool>(3)?)),
        )?;
        let partial = rows.len() > MAX_PATH_NEIGHBORS || rows.first().is_some_and(|row| row.3);
        Ok(CandidateBatch {
            entries: rows
                .into_iter()
                .take(MAX_PATH_NEIGHBORS)
                .map(|(kind, value, source, _)| (kind, value, source))
                .collect(),
            partial,
        })
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
