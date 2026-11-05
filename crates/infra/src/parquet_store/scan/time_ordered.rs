//! Bounded top-N scanning also prunes groups inside a compacted event file.
use super::time_bounds::{TimeBound, statistic_bound};
use super::{
    AppError, Instant, ParquetStore, RecordBatch, ScanSpec, ScanStatus, projection, row_filter,
    row_group_matches, rules_for_artifact, storage,
};
mod keys;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
};
use std::collections::BTreeMap;

#[derive(Clone)]
pub(in crate::parquet_store) struct TimeCutoff(
    pub(in crate::parquet_store) super::super::time_cell::TimeCell,
);

impl ParquetStore {
    pub(in crate::parquet_store) fn scan_time_ordered_file(
        &self,
        spec: ScanSpec<'_>,
        names: &BTreeMap<String, String>,
        newest: bool,
        mut cutoff: Option<TimeCutoff>,
        mut visit: impl FnMut(&RecordBatch) -> Result<Option<TimeCutoff>, AppError>,
    ) -> Result<ScanStatus, AppError> {
        let artifact = spec
            .artifacts
            .first()
            .ok_or_else(super::super::invalid_source)?;
        let Some(file) = self.verify_for_scan(&self.case_dir(spec.id)?, artifact, &spec)? else {
            return Ok(ScanStatus::Deadline);
        };
        let _scan = self
            .profile
            .as_ref()
            .map(|p| p.query_timer(super::super::profile::QueryPhase::Scan));
        let builder = ParquetRecordBatchReaderBuilder::try_new(file.try_clone().map_err(storage)?)
            .map_err(storage)?;
        super::super::format::validate_schema(artifact, builder.schema().as_ref())?;
        let precise = matches!(artifact, super::ParquetArtifact::V2(_));
        let rules = rules_for_artifact(&spec, precise)?;
        let groups = ordered_groups(&builder, &rules, newest)?;
        let metadata =
            ArrowReaderMetadata::try_new(builder.metadata().clone(), ArrowReaderOptions::default())
                .map_err(storage)?;
        let columns = super::required_columns(&spec, precise);
        for (bound, group) in groups {
            if cutoff.as_ref().is_some_and(|c| {
                bound.cannot_beat(c.0.time.map(irmind_app::IndexedTime::instant), newest)
            }) {
                break;
            }
            if spec.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if Instant::now() >= spec.deadline {
                return Ok(ScanStatus::Deadline);
            }
            if !precise
                && let Some(cutoff) = &cutoff
                && bound == TimeBound::Known(cutoff.0.time.map(irmind_app::IndexedTime::instant))
                && keys::cannot_beat(&file, &metadata, &spec, names, group, &cutoff.0)?
            {
                continue;
            }
            let reader = group_reader(&file, &metadata, &columns, &rules, group)?;
            for batch in reader {
                if spec.cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                if Instant::now() >= spec.deadline {
                    return Ok(ScanStatus::Deadline);
                }
                let normalize = self
                    .profile
                    .as_ref()
                    .map(|p| p.query_timer(super::super::profile::QueryPhase::Normalize));
                let batch = super::super::format::normalize_batch(
                    &batch.map_err(storage)?,
                    artifact,
                    names,
                )?;
                drop(normalize);
                let (batch, status) = self.filter_legacy_host(spec, names, batch)?;
                if status == ScanStatus::Deadline {
                    return Ok(status);
                }
                cutoff = visit(&batch)?;
            }
        }
        Ok(ScanStatus::Complete)
    }
}

fn ordered_groups(
    builder: &ParquetRecordBatchReaderBuilder<std::fs::File>,
    rules: &[super::Predicate],
    newest: bool,
) -> Result<Vec<(TimeBound, usize)>, AppError> {
    let index = builder.schema().index_of("event_time").map_err(storage)?;
    let mut groups = builder
        .metadata()
        .row_groups()
        .iter()
        .enumerate()
        .filter(|(_, group)| row_group_matches(builder, group, rules))
        .map(|(i, group)| {
            let bound = group
                .column(index)
                .statistics()
                .map_or(TimeBound::Unbounded, |s| {
                    statistic_bound(s, group.num_rows(), newest)
                });
            (bound, i)
        })
        .collect::<Vec<_>>();
    groups.sort_by(|(a, ia), (b, ib)| a.compare(*b, newest).then_with(|| ia.cmp(ib)));
    Ok(groups)
}

fn group_reader(
    file: &std::fs::File,
    metadata: &ArrowReaderMetadata,
    columns: &[&str],
    rules: &[super::Predicate],
    group: usize,
) -> Result<parquet::arrow::arrow_reader::ParquetRecordBatchReader, AppError> {
    let builder = ParquetRecordBatchReaderBuilder::new_with_metadata(
        file.try_clone().map_err(storage)?,
        metadata.clone(),
    );
    let selected = projection(&builder, columns)?;
    let filter = row_filter(&builder, rules)?;
    builder
        .with_projection(selected)
        .with_row_filter(filter)
        .with_row_groups(vec![group])
        .with_batch_size(4096)
        .build()
        .map_err(storage)
}
