use super::{
    AppError, CancellationToken, CaseId, GraphQueryFilter, Instant, Node, ParquetArtifact,
    QUERY_DEADLINE, QueryStore, ScanStatus, Selection, spec,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
const HOPS: usize = 3;
const EXPANSIONS: usize = 200;
const NEIGHBORS: usize = 50;
type Parents = BTreeMap<Node, (Option<Node>, String)>;
impl QueryStore<'_> {
    pub(in crate::parquet_store::query) fn scoped_path(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        from: (&str, &str),
        to: (&str, &str),
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if from == to {
            return Ok(format!(
                "{} {} is the same queried value; individual identity scopes remain distinct",
                from.0, from.1
            ));
        }
        let deadline = Instant::now() + QUERY_DEADLINE;
        let first = self.scoped_candidates(
            spec(id, artifacts, filter, cancel, deadline),
            Selection {
                kind: from.0,
                value: from.1,
                scope: None,
            },
        )?;
        if first.status == ScanStatus::Deadline {
            return Ok(truncated("10-second time budget"));
        }
        let mut parents = Parents::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut partial = first.sampled || first.neighbors.len() > NEIGHBORS;
        for (node, (_, source)) in first.neighbors.into_iter().take(NEIGHBORS) {
            parents.insert(node.clone(), (None, source));
            visited.insert(node.clone());
            if node.matches(to.0, to.1) {
                return format_path(from, &node, &parents);
            }
            queue.push_back((node, 1usize));
        }
        let mut expanded = 1;
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= HOPS {
                continue;
            }
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if expanded >= EXPANSIONS {
                return Ok(truncated("200-entity expansion limit"));
            }
            if Instant::now() >= deadline {
                return Ok(truncated("10-second time budget"));
            }
            expanded += 1;
            let result = self.scoped_candidates(
                spec(id, artifacts, filter, cancel, deadline),
                Selection {
                    kind: &current.kind,
                    value: &current.value,
                    scope: Some(&current.scope),
                },
            )?;
            if result.status == ScanStatus::Deadline {
                return Ok(truncated("10-second time budget"));
            }
            partial |= result.sampled || result.neighbors.len() > NEIGHBORS;
            for (next, (_, source)) in result.neighbors.into_iter().take(NEIGHBORS) {
                if !visited.insert(next.clone()) {
                    continue;
                }
                parents.insert(next.clone(), (Some(current.clone()), source));
                if next.matches(to.0, to.1) {
                    return format_path(from, &next, &parents);
                }
                queue.push_back((next, depth + 1));
            }
        }
        Ok(if partial {
            truncated("sample or 50-neighbor limit")
        } else {
            "no co-observation path found within 3 hops".into()
        })
    }
}
fn truncated(reason: &str) -> String {
    format!(
        "no path found within 3 hops / 200 expanded entities / 50 neighbors per entity / 10 seconds; search was truncated ({reason})"
    )
}
fn format_path(start: (&str, &str), goal: &Node, parents: &Parents) -> Result<String, AppError> {
    let mut lines = Vec::new();
    let mut current = goal;
    for _ in 0..HOPS {
        let (parent, source) = parents
            .get(current)
            .ok_or_else(crate::parquet_store::invalid_source)?;
        if let Some(parent) = parent {
            lines.push(format!(
                "{} --[co-observed in {source}]--> {}",
                parent.display(),
                current.display()
            ));
            current = parent;
        } else {
            lines.push(format!(
                "{} {} [matching scoped occurrence] --[co-observed in {source}]--> {}",
                start.0,
                start.1,
                current.display()
            ));
            lines.reverse();
            return Ok(lines.join("\n"));
        }
    }
    Err(crate::parquet_store::invalid_source())
}
