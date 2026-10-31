use super::{AppError, CancellationToken, CaseId, ParquetArtifactV1, ParquetStore};
use crate::parquet_store::scan::{Predicate, ScanFlow, ScanSpec, ScanStatus};
use arrow::array::{StringArray, UInt64Array};
use arrow::record_batch::RecordBatch;
use irmind_domain::GraphQueryFilter;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

mod coobservations;
mod entity;
mod events;
mod neighbors;
mod path;
use coobservations::coobservation_available;

pub(super) const QUERY_DEADLINE: Duration = Duration::from_secs(10);
pub(super) const MAX_NEIGHBOR_RECORDS: usize = 4096;

pub(super) struct TargetScan {
    pub records: HashMap<String, HashSet<u64>>,
    pub sampled: bool,
    pub status: ScanStatus,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct EventHit {
    at: String,
    event: String,
    hash: String,
    index: u64,
}

impl EventHit {
    fn from_batch(batch: &RecordBatch, row: usize) -> Result<Self, AppError> {
        Ok(Self {
            at: text(batch, "event_time", row)?.into(),
            event: text(batch, "event", row)?.into(),
            hash: text(batch, "source_hash", row)?.into(),
            index: number(batch, "record_index", row)?,
        })
    }

    fn source(&self) -> String {
        format!("{}#{}", self.hash, self.index)
    }
}

pub(super) fn text<'a>(
    batch: &'a RecordBatch,
    name: &str,
    row: usize,
) -> Result<&'a str, AppError> {
    batch
        .column_by_name(name)
        .and_then(|column| column.as_any().downcast_ref::<StringArray>())
        .map(|column| column.value(row))
        .ok_or_else(|| AppError::Policy("invalid Parquet text column".into()))
}

pub(super) fn number(batch: &RecordBatch, name: &str, row: usize) -> Result<u64, AppError> {
    batch
        .column_by_name(name)
        .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
        .map(|column| column.value(row))
        .ok_or_else(|| AppError::Policy("invalid Parquet number column".into()))
}

pub(super) fn time_rules(filter: &GraphQueryFilter) -> Vec<Predicate> {
    filter.time_range().map_or_else(Vec::new, |(from, to)| {
        vec![Predicate::Range("event_time", from.into(), to.into())]
    })
}

pub(super) fn complete(status: ScanStatus) -> Result<(), AppError> {
    if status == ScanStatus::Deadline {
        Err(AppError::Policy(
            "Parquet query exceeded 10-second budget".into(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn recent(rows: &mut Vec<EventHit>, limit: usize) {
    rows.sort_by(|left, right| {
        right
            .at
            .cmp(&left.at)
            .then_with(|| left.hash.cmp(&right.hash))
            .then_with(|| left.index.cmp(&right.index))
    });
    rows.truncate(limit);
}
