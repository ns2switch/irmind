use super::{AppError, CancellationToken, CaseId, ParquetArtifact, ParquetStore};
use crate::parquet_store::scan::{Predicate, ScanFlow, ScanSpec, ScanStatus};
use arrow::array::{StringArray, UInt64Array};
use arrow::record_batch::RecordBatch;
use irmind_domain::GraphQueryFilter;
use std::time::{Duration, Instant};

pub(crate) struct QueryStore<'a> {
    store: &'a ParquetStore,
    source_names: &'a std::collections::BTreeMap<String, String>,
}
impl ParquetStore {
    pub(crate) fn queries<'a>(
        &'a self,
        names: &'a std::collections::BTreeMap<String, String>,
    ) -> QueryStore<'a> {
        QueryStore {
            store: self,
            source_names: names,
        }
    }
}
impl QueryStore<'_> {
    fn scan_artifacts(
        &self,
        spec: ScanSpec<'_>,
        visit: impl FnMut(&RecordBatch) -> Result<ScanFlow, AppError>,
    ) -> Result<ScanStatus, AppError> {
        require_current(spec.artifacts)?;
        self.store.scan_artifacts(spec, self.source_names, visit)
    }
}

mod coobservations;
mod entity;
mod events;
mod extrema;
mod neighbors;
mod path;
mod retained;
mod scoped;
mod timeline;
use coobservations::coobservation_available;

pub(super) const QUERY_DEADLINE: Duration = Duration::from_secs(10);
pub(super) const MAX_NEIGHBOR_RECORDS: usize = 4096;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct EventHit {
    at: String,
    event: String,
    hash: String,
    index: u64,
    time: super::time_cell::TimeCell,
    show_precision: bool,
}

impl EventHit {
    fn from_batch(batch: &RecordBatch, row: usize, show_precision: bool) -> Result<Self, AppError> {
        let time = super::time_cell::TimeCell::from_batch(batch, row)?;
        let at = batch
            .column_by_name("event_time")
            .and_then(|a| a.as_any().downcast_ref::<StringArray>())
            .map_or_else(|| time.display(), |a| a.value(row).into());
        Ok(Self {
            show_precision,
            at,
            event: text(batch, "event", row)?.into(),
            hash: text(batch, "source_hash", row)?.into(),
            index: number(batch, "record_index", row)?,
            time,
        })
    }

    fn annotated_event(&self) -> String {
        if self.show_precision {
            format!("{} [{}]", self.event, self.time.note())
        } else {
            self.event.clone()
        }
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

pub(super) fn recent(rows: &mut Vec<EventHit>, limit: usize) -> Result<(), AppError> {
    ordered(rows, limit, true)
}

fn ordered(rows: &mut Vec<EventHit>, limit: usize, newest: bool) -> Result<(), AppError> {
    let mut error = None;
    rows.sort_by(|left, right| match left.time.compare(&right.time, newest) {
        Ok(order) => order,
        Err(failure) => {
            error = Some(failure);
            std::cmp::Ordering::Equal
        }
    });
    if let Some(error) = error {
        return Err(error);
    }
    rows.dedup_by(|a, b| a.hash == b.hash && a.index == b.index);
    rows.truncate(limit);
    Ok(())
}

fn require_current(artifacts: &[ParquetArtifact]) -> Result<(), AppError> {
    if artifacts
        .iter()
        .all(|a| matches!(a, ParquetArtifact::V3(_)))
    {
        Ok(())
    } else {
        Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredCaseFormat,
        ))
    }
}
