use super::{Node, Peer};
use crate::parquet_store::query::{MAX_NEIGHBOR_RECORDS, QueryStore, number, text, time_rules};
use crate::parquet_store::scan::{Predicate, ScanFlow, ScanSpec, ScanStatus};
use crate::parquet_store::{AppError, invalid_source, storage};
use arrow::{
    array::{Array, UInt8Array, UInt16Array},
    record_batch::RecordBatch,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Candidates {
    pub(super) neighbors: BTreeMap<Node, (u64, String)>,
    pub(super) sampled: bool,
    pub(super) status: ScanStatus,
}
#[derive(Clone, Copy)]
pub(super) struct Selection<'a> {
    pub(super) kind: &'a str,
    pub(super) value: &'a str,
    pub(super) scope: Option<&'a str>,
}
impl QueryStore<'_> {
    pub(in crate::parquet_store::query::scoped) fn scoped_candidates(
        &self,
        mut spec: ScanSpec<'_>,
        selected: Selection<'_>,
    ) -> Result<Candidates, AppError> {
        if !crate::parquet_store::query::coobservation_available(spec.artifacts, spec.filter) {
            return self.scoped_from_entities(spec, selected);
        }
        let mut rules = time_rules(spec.filter);
        rules.extend([
            Predicate::Equal("entity_kind", selected.kind.into()),
            Predicate::Equal("entity_value", selected.value.into()),
        ]);
        spec.schema = "irmind-coobservations-v1";
        spec.columns = &[
            "entity_kind",
            "entity_value",
            "identity_scope",
            "entity_role",
            "entity_field",
            "co_entities",
            "co_observations",
            "source_hash",
            "record_index",
        ];
        let mut neighbors = BTreeMap::<Node, (u64, String)>::new();
        let mut times = BTreeMap::<Node, crate::parquet_store::time_cell::TimeCell>::new();
        let mut records = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut sampled = false;
        let status = self.scan_artifacts(
            ScanSpec {
                predicates: &rules,
                ..spec
            },
            |batch| {
                for row in 0..batch.num_rows() {
                    let subject = subject(batch, row)?;
                    if selected.scope.is_some_and(|scope| scope != subject.scope) {
                        continue;
                    }
                    let hash = text(batch, "source_hash", row)?;
                    let index = number(batch, "record_index", row)?;
                    records.insert((hash.to_owned(), index));
                    if records.len() > MAX_NEIGHBOR_RECORDS {
                        sampled = true;
                        return Ok(ScanFlow::Stop);
                    }
                    let source = format!("{hash}#{index}");
                    let time = crate::parquet_store::time_cell::TimeCell::from_batch(batch, row)?;
                    for peer in peers(batch, row)? {
                        if peer == subject || !seen.insert((peer.clone(), hash.to_owned(), index)) {
                            continue;
                        }
                        let entry = neighbors
                            .entry(peer.clone())
                            .or_insert_with(|| (0, source.clone()));
                        entry.0 += 1;
                        if times
                            .get(&peer)
                            .map(|old| time.compare(old, false))
                            .transpose()?
                            .is_none_or(std::cmp::Ordering::is_lt)
                        {
                            entry.1.clone_from(&source);
                            times.insert(peer, time.clone());
                        }
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
pub(super) fn subject(batch: &RecordBatch, row: usize) -> Result<Node, AppError> {
    let role = batch
        .column_by_name("entity_role")
        .and_then(|c| c.as_any().downcast_ref::<UInt8Array>())
        .ok_or_else(invalid_source)?;
    let field = batch
        .column_by_name("entity_field")
        .and_then(|c| c.as_any().downcast_ref::<UInt16Array>())
        .ok_or_else(invalid_source)?;
    if role.is_null(row) || field.is_null(row) {
        return Err(invalid_source());
    }
    Node::checked(
        text(batch, "entity_kind", row)?,
        text(batch, "entity_value", row)?,
        text(batch, "identity_scope", row)?,
        role.value(row),
        field.value(row),
    )
}
fn peers(batch: &RecordBatch, row: usize) -> Result<Vec<Node>, AppError> {
    if batch.column_by_name("co_observations").is_some() {
        let raw = text(batch, "co_observations", row)?;
        if raw.len() > 64 * 1024 * 1024 {
            return Err(invalid_source());
        }
        let peers: Vec<Peer<'_>> = serde_json::from_str(raw).map_err(storage)?;
        peers.iter().map(Peer::node).collect()
    } else {
        let raw = text(batch, "co_entities", row)?;
        if raw.len() > 64 * 1024 * 1024 {
            return Err(invalid_source());
        }
        let peers: Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)> =
            serde_json::from_str(raw).map_err(storage)?;
        Ok(peers
            .into_iter()
            .map(|(kind, value)| Node::legacy(&kind, &value))
            .collect())
    }
}
