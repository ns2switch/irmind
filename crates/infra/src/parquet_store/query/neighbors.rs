use super::{
    AppError, CancellationToken, CaseId, GraphQueryFilter, Instant, MAX_NEIGHBOR_RECORDS,
    ParquetArtifactV1, ParquetStore, Predicate, QUERY_DEADLINE, ScanFlow, ScanSpec, TargetScan,
    complete, number, text, time_rules,
};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

impl ParquetStore {
    pub(crate) fn neighbors_native(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let deadline = Instant::now() + QUERY_DEADLINE;
        let TargetScan {
            records: targets,
            sampled,
            status: target_status,
        } = self.native_targets(id, artifacts, filter, entity, deadline, cancel)?;
        complete(target_status)?;
        let mut counts = BTreeMap::<(String, String), u64>::new();
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
                    if !targets.contains(&(hash.to_owned(), index)) {
                        continue;
                    }
                    let kind = text(batch, "entity_kind", row)?;
                    let value = text(batch, "entity_value", row)?;
                    if (kind, value) != entity {
                        *counts.entry((kind.into(), value.into())).or_default() += 1;
                    }
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        complete(status)?;
        let mut rows = counts.into_iter().collect::<Vec<_>>();
        rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        rows.truncate(limit.min(20));
        if rows.is_empty() {
            return Ok("no neighbors in the bounded Parquet query; refine the entity".into());
        }
        let mut output = rows
            .into_iter()
            .map(|((kind, value), count)| format!("{kind} {value} co-observed {count} times"))
            .collect::<Vec<_>>()
            .join("\n");
        if sampled {
            write!(output, "\nPartial result: sampled {MAX_NEIGHBOR_RECORDS} matching records; refine the entity to narrow the search.").map_err(super::super::storage)?;
        }
        Ok(output)
    }

    pub(super) fn native_targets(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<TargetScan, AppError> {
        let mut rules = time_rules(filter);
        rules.extend([
            Predicate::Equal("entity_kind", entity.0.into()),
            Predicate::Equal("entity_value", entity.1.into()),
        ]);
        let mut targets = HashSet::new();
        let mut count = 0usize;
        let status = self.scan_artifacts(
            ScanSpec {
                id,
                artifacts,
                filter,
                schema: "irmind-entities-v1",
                columns: &["source_hash", "record_index"],
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
                    targets.insert((
                        text(batch, "source_hash", row)?.into(),
                        number(batch, "record_index", row)?,
                    ));
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        Ok(TargetScan {
            records: targets,
            sampled: count > MAX_NEIGHBOR_RECORDS,
            status,
        })
    }
}
