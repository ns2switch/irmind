use super::{AppError, CancellationToken, CaseId, ParquetArtifact, ParquetStore, Path, storage};
use arrow::array::BooleanArray;
use arrow::datatypes::DataType;
use arrow::record_batch::RecordBatch;
use irmind_domain::GraphQueryFilter;
use parquet::arrow::ProjectionMask;
use parquet::arrow::arrow_reader::{ArrowPredicateFn, ParquetRecordBatchReaderBuilder, RowFilter};
use parquet::file::properties::ReaderProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::serialized_reader::ReadOptionsBuilder;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::Instant;

pub(super) const MAX_QUERY_FILES: usize = 8192;
const FILE_WORKERS: usize = 4;
mod common;
mod selection;
pub(super) use selection::partition_matches;
use selection::{required_columns, rules_for_artifact};
mod host;
mod predicate;
mod time_bounds;
mod time_ordered;
pub(super) use time_ordered::TimeCutoff;
mod verification;
pub(super) use predicate::Predicate;
#[cfg(test)]
use predicate::contains_ignore_case;

#[derive(Clone, Copy)]
pub(super) struct ScanSpec<'a> {
    pub id: &'a CaseId,
    pub artifacts: &'a [ParquetArtifact],
    pub filter: &'a GraphQueryFilter,
    pub schema: &'a str,
    pub columns: &'a [&'a str],
    pub predicates: &'a [Predicate],
    pub deadline: Instant,
    pub cancel: &'a CancellationToken,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ScanFlow {
    Continue,
    Stop,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ScanStatus {
    Complete,
    Stopped,
    Deadline,
}

enum ScanMessage {
    Batch(RecordBatch),
    Done(ScanStatus),
}

impl ParquetStore {
    pub(super) fn scan_artifacts(
        &self,
        spec: ScanSpec<'_>,
        source_names: &std::collections::BTreeMap<String, String>,
        mut visit: impl FnMut(&RecordBatch) -> Result<ScanFlow, AppError>,
    ) -> Result<ScanStatus, AppError> {
        let selected = spec
            .artifacts
            .iter()
            .filter(|artifact| {
                super::format::same_family(artifact.schema_version(), spec.schema)
                    && partition_matches(artifact, spec.filter)
            })
            .collect::<Vec<_>>();
        if selected.len() > MAX_QUERY_FILES {
            return Err(AppError::Policy(
                "too many Parquet partitions; narrow the query".into(),
            ));
        }
        let case_dir = self.case_dir(spec.id)?;
        let mut source_units = std::collections::BTreeMap::new();
        for group in selected.chunks(FILE_WORKERS) {
            let status = std::thread::scope(|scope| {
                let receivers = group
                    .iter()
                    .map(|artifact| {
                        let (sender, receiver) = sync_channel(1);
                        let case_dir = case_dir.clone();
                        scope.spawn(move || {
                            let result = self.scan_one_artifact(
                                &case_dir,
                                artifact,
                                &spec,
                                source_names,
                                &sender,
                            );
                            let message = result.map(ScanMessage::Done);
                            let _ = sender.send(message);
                        });
                        receiver
                    })
                    .collect::<Vec<_>>();
                for receiver in receivers {
                    loop {
                        let message = receiver.recv().map_err(storage)??;
                        match message {
                            ScanMessage::Batch(batch) => {
                                super::time_cell::validate_source_units(&batch, &mut source_units)?;
                                let (batch, host_status) =
                                    self.filter_legacy_host(spec, source_names, batch)?;
                                if host_status == ScanStatus::Deadline {
                                    return Ok(host_status);
                                }
                                if visit(&batch)? == ScanFlow::Stop {
                                    return Ok(ScanStatus::Stopped);
                                }
                            }
                            ScanMessage::Done(ScanStatus::Complete) => break,
                            ScanMessage::Done(other) => return Ok(other),
                        }
                    }
                }
                Ok(ScanStatus::Complete)
            })?;
            if status != ScanStatus::Complete {
                return Ok(status);
            }
        }
        Ok(ScanStatus::Complete)
    }

    fn scan_one_artifact(
        &self,
        case_dir: &Path,
        artifact: &ParquetArtifact,
        spec: &ScanSpec<'_>,
        source_names: &std::collections::BTreeMap<String, String>,
        sender: &SyncSender<Result<ScanMessage, AppError>>,
    ) -> Result<ScanStatus, AppError> {
        let Some(file) = self.verify_for_scan(case_dir, artifact, spec)? else {
            return Ok(ScanStatus::Deadline);
        };
        let _scan = self
            .profile
            .as_ref()
            .map(|p| p.query_timer(super::profile::QueryPhase::Scan));
        let precise = matches!(artifact, ParquetArtifact::V2(_));
        let rules = rules_for_artifact(spec, precise, artifact)?;
        let bloom = bloom_reader(&file, artifact, &rules)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).map_err(storage)?;
        super::format::validate_schema(artifact, builder.schema().as_ref())?;
        let columns = required_columns(spec, precise, common::supported(artifact));
        let required = projection(&builder, &columns)?;
        let mut groups = Vec::new();
        for (index, group) in builder.metadata().row_groups().iter().enumerate() {
            if row_group_matches(&builder, group, &rules)
                && bloom_matches(bloom.as_ref(), index, &builder, &rules)?
            {
                groups.push(index);
            }
        }
        if groups.is_empty() {
            return Ok(ScanStatus::Complete);
        }
        let filter = row_filter(&builder, &rules)?;
        let mut reader = builder
            .with_row_groups(groups)
            .with_projection(required)
            .with_row_filter(filter)
            .with_batch_size(4096)
            .build()
            .map_err(storage)?;
        for batch in &mut reader {
            if spec.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if Instant::now() >= spec.deadline {
                return Ok(ScanStatus::Deadline);
            }
            let normalize = self
                .profile
                .as_ref()
                .map(|p| p.query_timer(super::profile::QueryPhase::Normalize));
            let normalized = super::format::normalize_batch(
                &batch.map_err(storage)?,
                artifact,
                source_names,
                spec.columns != ["event_time"],
            )?;
            let normalized = common::projection_defaults(normalized, spec, artifact)?;
            drop(normalize);
            if sender.send(Ok(ScanMessage::Batch(normalized))).is_err() {
                return Ok(ScanStatus::Stopped);
            }
        }
        Ok(ScanStatus::Complete)
    }
}

fn bloom_reader(
    file: &std::fs::File,
    artifact: &ParquetArtifact,
    predicates: &[Predicate],
) -> Result<Option<SerializedFileReader<std::fs::File>>, AppError> {
    if !predicates
        .iter()
        .any(|predicate| matches!(predicate, Predicate::Equal("entity_value", _)))
        || !matches!(
            artifact.schema_version(),
            "irmind-entities-v2"
                | "irmind-entities-v3"
                | "irmind-entities-v4"
                | "irmind-coobservations-v1"
                | "irmind-coobservations-v2"
                | "irmind-coobservations-v3"
        )
    {
        return Ok(None);
    }
    SerializedFileReader::new_with_options(
        file.try_clone().map_err(storage)?,
        ReadOptionsBuilder::new()
            .with_reader_properties(
                ReaderProperties::builder()
                    .set_read_bloom_filter(true)
                    .build(),
            )
            .build(),
    )
    .map(Some)
    .map_err(storage)
}

fn bloom_matches(
    reader: Option<&SerializedFileReader<std::fs::File>>,
    row_group: usize,
    builder: &ParquetRecordBatchReaderBuilder<std::fs::File>,
    predicates: &[Predicate],
) -> Result<bool, AppError> {
    let Some(reader) = reader else {
        return Ok(true);
    };
    let Some(value) = predicates.iter().find_map(|predicate| match predicate {
        Predicate::Equal("entity_value", value) => Some(value),
        _ => None,
    }) else {
        return Ok(true);
    };
    let column = builder.schema().index_of("entity_value").map_err(storage)?;
    let group = reader.get_row_group(row_group).map_err(storage)?;
    Ok(group
        .get_column_bloom_filter(column)
        .is_none_or(|filter| filter.check(&value.as_str())))
}

fn projection(
    builder: &ParquetRecordBatchReaderBuilder<std::fs::File>,
    columns: &[&str],
) -> Result<ProjectionMask, AppError> {
    let mut indexes = Vec::with_capacity(columns.len());
    for name in columns {
        let index = builder.schema().index_of(name).map_err(storage)?;
        let field = builder.schema().field(index);
        let precise = matches!(
            builder
                .schema()
                .field_with_name("event_time")
                .map(arrow::datatypes::Field::data_type),
            Ok(DataType::Timestamp(_, _))
        );
        let expected = super::format::expected_type(name, precise);
        if field.data_type() != &expected {
            return Err(super::invalid_source());
        }
        indexes.push(index);
    }
    Ok(ProjectionMask::roots(builder.parquet_schema(), indexes))
}

fn row_filter(
    builder: &ParquetRecordBatchReaderBuilder<std::fs::File>,
    predicates: &[Predicate],
) -> Result<RowFilter, AppError> {
    if predicates.is_empty() {
        return Ok(RowFilter::new(Vec::new()));
    }
    let mut names = predicates.iter().map(Predicate::column).collect::<Vec<_>>();
    if predicates
        .iter()
        .any(|p| matches!(p, Predicate::TimeRange(..)))
        && matches!(
            builder
                .schema()
                .field_with_name("event_time")
                .map(arrow::datatypes::Field::data_type),
            Ok(DataType::Timestamp(_, _))
        )
    {
        names.push("submicro_nanos");
    }
    names.sort_unstable();
    names.dedup();
    let projection = projection(builder, &names)?;
    let rules = predicates.to_vec();
    let predicate = ArrowPredicateFn::new(projection, move |batch: RecordBatch| {
        let mut values = Vec::with_capacity(batch.num_rows());
        for row in 0..batch.num_rows() {
            let mut matches = true;
            for rule in &rules {
                matches &= rule.matches(&batch, row)?;
                if !matches {
                    break;
                }
            }
            values.push(Some(matches));
        }
        Ok(BooleanArray::from(values))
    });
    Ok(RowFilter::new(vec![Box::new(predicate)]))
}

fn row_group_matches(
    builder: &ParquetRecordBatchReaderBuilder<std::fs::File>,
    group: &parquet::file::metadata::RowGroupMetaData,
    predicates: &[Predicate],
) -> bool {
    predicates.iter().all(|rule| {
        if let Predicate::TimeRange(from, to) = rule {
            let Ok(index) = builder.schema().index_of("event_time") else {
                return true;
            };
            if let Some(parquet::file::statistics::Statistics::Int64(stats)) =
                group.column(index).statistics()
            {
                return stats
                    .min_opt()
                    .zip(stats.max_opt())
                    .is_none_or(|(min, max)| {
                        *min <= to.unix_micros() && *max >= from.unix_micros()
                    });
            }
            return true;
        }
        if matches!(rule, Predicate::SmallEqual(..) | Predicate::Mask(..)) {
            return builder
                .schema()
                .index_of(rule.column())
                .ok()
                .and_then(|index| group.column(index).statistics())
                .is_none_or(|stats| rule.may_match_numeric_statistics(stats));
        }
        let (name, lower, upper) = match rule {
            Predicate::Equal(name, value) => (*name, value.as_bytes(), value.as_bytes()),
            Predicate::Range(name, first, last) => (*name, first.as_bytes(), last.as_bytes()),
            _ => return true,
        };
        let Ok(index) = builder.schema().index_of(name) else {
            return true;
        };
        let Some(statistics) = group.column(index).statistics() else {
            return true;
        };
        match (statistics.min_bytes_opt(), statistics.max_bytes_opt()) {
            (Some(min), Some(max)) => min <= upper && max >= lower,
            _ => true,
        }
    })
}

#[cfg(test)]
mod tests;
