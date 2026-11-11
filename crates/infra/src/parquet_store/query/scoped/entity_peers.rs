//! Typed entity fallback for a selected inventory without complete co-observations.
use super::scan::{Candidates, subject};
use super::{Node, Selection};
use crate::parquet_store::query::{MAX_NEIGHBOR_RECORDS, QueryStore, number, text, time_rules};
use crate::parquet_store::scan::{Predicate, ScanFlow, ScanSpec, ScanStatus};
use crate::parquet_store::{AppError, time_cell::TimeCell};
use std::collections::{BTreeMap, BTreeSet};
const COLUMNS: &[&str] = &[
    "entity_kind",
    "entity_value",
    "identity_scope",
    "entity_role",
    "entity_field",
    "source_hash",
    "record_index",
];
type Record = (String, u64);
impl QueryStore<'_> {
    pub(in crate::parquet_store::query::scoped) fn scoped_from_entities(
        &self,
        spec: ScanSpec<'_>,
        selected: Selection<'_>,
    ) -> Result<Candidates, AppError> {
        let mut rules = time_rules(spec.filter);
        rules.extend([
            Predicate::Equal("entity_kind", selected.kind.into()),
            Predicate::Equal("entity_value", selected.value.into()),
        ]);
        let mut targets = BTreeMap::<Record, BTreeSet<Node>>::new();
        let mut sampled = false;
        let status = self.scan_artifacts(
            ScanSpec {
                schema: "irmind-entities-v4",
                columns: COLUMNS,
                predicates: &rules,
                ..spec
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    let node = subject(batch, row)?;
                    if selected.scope.is_some_and(|scope| scope != node.scope) {
                        continue;
                    }
                    let record = (
                        text(batch, "source_hash", row)?.into(),
                        number(batch, "record_index", row)?,
                    );
                    if !targets.contains_key(&record) && targets.len() == MAX_NEIGHBOR_RECORDS {
                        sampled = true;
                        return Ok(ScanFlow::Stop);
                    }
                    targets.entry(record).or_default().insert(node);
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        if status == ScanStatus::Deadline {
            return Ok(Candidates {
                neighbors: BTreeMap::new(),
                sampled,
                status,
            });
        }
        self.scoped_entity_peers(spec, &targets, sampled)
    }
    fn scoped_entity_peers(
        &self,
        spec: ScanSpec<'_>,
        targets: &BTreeMap<Record, BTreeSet<Node>>,
        sampled: bool,
    ) -> Result<Candidates, AppError> {
        let mut common = spec.filter.common();
        common.role = None;
        let filter = spec.filter.clone().with_common(common);
        let mut neighbors = BTreeMap::<Node, (u64, String)>::new();
        let mut earliest = BTreeMap::<Node, TimeCell>::new();
        let mut seen = BTreeSet::new();
        let status = self.scan_artifacts(
            ScanSpec {
                filter: &filter,
                schema: "irmind-entities-v4",
                columns: COLUMNS,
                predicates: &time_rules(&filter),
                ..spec
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    let hash = text(batch, "source_hash", row)?;
                    let index = number(batch, "record_index", row)?;
                    let Some(subjects) = targets.get(&(hash.into(), index)) else {
                        continue;
                    };
                    let peer = subject(batch, row)?;
                    if subjects.contains(&peer)
                        || !seen.insert((peer.clone(), hash.to_owned(), index))
                    {
                        continue;
                    }
                    let time = TimeCell::from_batch(batch, row)?;
                    let source = format!("{hash}#{index}");
                    let entry = neighbors
                        .entry(peer.clone())
                        .or_insert_with(|| (0, source.clone()));
                    entry.0 += 1;
                    if earliest
                        .get(&peer)
                        .map(|old| time.compare(old, false))
                        .transpose()?
                        .is_none_or(std::cmp::Ordering::is_lt)
                    {
                        entry.1.clone_from(&source);
                        earliest.insert(peer, time);
                    }
                }
                Ok(ScanFlow::Continue)
            },
        )?;
        Ok(Candidates {
            neighbors,
            sampled,
            status,
        })
    }
}
