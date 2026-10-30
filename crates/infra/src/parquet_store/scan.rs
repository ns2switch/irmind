use super::{
    AppError, CancellationToken, CaseId, ParquetArtifactV1, ParquetStore, Path, Seek, SeekFrom,
    storage,
};
use arrow::array::{Array, BooleanArray, StringArray, UInt64Array};
use arrow::datatypes::DataType;
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;
use irmind_domain::GraphQueryFilter;
use memchr::{memchr, memchr2};
use parquet::arrow::ProjectionMask;
use parquet::arrow::arrow_reader::{ArrowPredicateFn, ParquetRecordBatchReaderBuilder, RowFilter};
use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::Instant;

pub(super) const MAX_QUERY_FILES: usize = 8192;
const FILE_WORKERS: usize = 4;

#[derive(Clone, Copy)]
pub(super) struct ScanSpec<'a> {
    pub id: &'a CaseId,
    pub artifacts: &'a [ParquetArtifactV1],
    pub filter: &'a GraphQueryFilter,
    pub schema: &'a str,
    pub columns: &'a [&'a str],
    pub predicates: &'a [Predicate],
    pub deadline: Instant,
    pub cancel: &'a CancellationToken,
}

#[derive(Clone)]
pub(super) enum Predicate {
    Equal(&'static str, String),
    Range(&'static str, String, String),
    ContainsIgnoreCase(&'static str, String),
    Index(u64),
}

impl Predicate {
    fn column(&self) -> &'static str {
        match self {
            Self::Equal(column, _)
            | Self::Range(column, _, _)
            | Self::ContainsIgnoreCase(column, _) => column,
            Self::Index(_) => "record_index",
        }
    }

    fn matches(&self, batch: &RecordBatch, row: usize) -> Result<bool, ArrowError> {
        let column = batch
            .column_by_name(self.column())
            .ok_or_else(|| ArrowError::SchemaError("missing Parquet predicate column".into()))?;
        if let Self::Index(index) = self {
            let values = column
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| {
                    ArrowError::SchemaError("invalid Parquet record index column".into())
                })?;
            Ok(!values.is_null(row) && values.value(row) == *index)
        } else {
            let values = column
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| ArrowError::SchemaError("invalid Parquet text column".into()))?;
            if values.is_null(row) {
                return Ok(false);
            }
            let value = values.value(row);
            Ok(match self {
                Self::Equal(_, expected) => value == expected,
                Self::Range(_, first, last) => value >= first.as_str() && value <= last.as_str(),
                Self::ContainsIgnoreCase(_, needle) => contains_ignore_case(value, needle),
                Self::Index(_) => false,
            })
        }
    }
}

pub(super) fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_ascii() {
        let bytes = haystack.as_bytes();
        let target = needle.as_bytes();
        if target.is_empty() {
            return true;
        }
        if target.len() > bytes.len() {
            return false;
        }
        let last = target[target.len() - 1];
        let mut offset = target.len() - 1;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            let found = if last.is_ascii_alphabetic() {
                memchr2(
                    last.to_ascii_lowercase(),
                    last.to_ascii_uppercase(),
                    remaining,
                )
            } else {
                memchr(last, remaining)
            };
            let Some(found) = found else { break };
            let end = offset + found + 1;
            if bytes[end - target.len()..end].eq_ignore_ascii_case(target) {
                return true;
            }
            offset = end;
        }
        return false;
    }
    haystack.to_lowercase().contains(&needle.to_lowercase())
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
        mut visit: impl FnMut(&RecordBatch) -> Result<ScanFlow, AppError>,
    ) -> Result<ScanStatus, AppError> {
        let selected = spec
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.schema_version == spec.schema && partition_matches(artifact, spec.filter)
            })
            .collect::<Vec<_>>();
        if selected.len() > MAX_QUERY_FILES {
            return Err(AppError::Policy(
                "too many Parquet partitions; narrow the query".into(),
            ));
        }
        let case_dir = self.case_dir(spec.id)?;
        for group in selected.chunks(FILE_WORKERS) {
            let status = std::thread::scope(|scope| {
                let receivers = group
                    .iter()
                    .map(|artifact| {
                        let (sender, receiver) = sync_channel(1);
                        let case_dir = case_dir.clone();
                        scope.spawn(move || {
                            let result =
                                self.scan_one_artifact(&case_dir, artifact, &spec, &sender);
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
        artifact: &ParquetArtifactV1,
        spec: &ScanSpec<'_>,
        sender: &SyncSender<Result<ScanMessage, AppError>>,
    ) -> Result<ScanStatus, AppError> {
        if spec.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if Instant::now() >= spec.deadline {
            return Ok(ScanStatus::Deadline);
        }
        artifact.validate().map_err(|_| super::invalid_source())?;
        let verify_started = Instant::now();
        let mut file = irmind_fs::open_regular_no_follow(case_dir, Path::new(&artifact.path))
            .map_err(storage)?;
        let Some((digest, size)) = hash_until_deadline(&mut file, spec.cancel, spec.deadline)?
        else {
            return Ok(ScanStatus::Deadline);
        };
        if size != artifact.size || digest != super::parse_hash(&artifact.sha256)? {
            return Err(AppError::EvidenceMismatch(artifact.sha256.as_str().into()));
        }
        file.seek(SeekFrom::Start(0)).map_err(storage)?;
        if let Some(profile) = &self.profile {
            profile.record_query_verify(verify_started.elapsed());
        }
        let scan_started = Instant::now();
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).map_err(storage)?;
        let required = projection(&builder, spec.columns)?;
        let groups = builder
            .metadata()
            .row_groups()
            .iter()
            .enumerate()
            .filter_map(|(index, group)| {
                row_group_matches(&builder, group, spec.predicates).then_some(index)
            })
            .collect::<Vec<_>>();
        if groups.is_empty() {
            return Ok(ScanStatus::Complete);
        }
        let filter = row_filter(&builder, spec.predicates)?;
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
            if sender
                .send(Ok(ScanMessage::Batch(batch.map_err(storage)?)))
                .is_err()
            {
                return Ok(ScanStatus::Stopped);
            }
        }
        if let Some(profile) = &self.profile {
            profile.record_query_scan(scan_started.elapsed());
        }
        Ok(ScanStatus::Complete)
    }
}

fn hash_until_deadline(
    file: &mut std::fs::File,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Option<([u8; 32], u64)>, AppError> {
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let count = file.read(&mut buffer).map_err(storage)?;
        if count == 0 {
            return Ok(Some((hasher.finalize().into(), size)));
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| AppError::Policy("Parquet size overflow".into()))?;
        hasher.update(&buffer[..count]);
    }
}

fn projection(
    builder: &ParquetRecordBatchReaderBuilder<std::fs::File>,
    columns: &[&str],
) -> Result<ProjectionMask, AppError> {
    let mut indexes = Vec::with_capacity(columns.len());
    for name in columns {
        let index = builder.schema().index_of(name).map_err(storage)?;
        let field = builder.schema().field(index);
        let expected = if *name == "record_index" {
            DataType::UInt64
        } else {
            DataType::Utf8
        };
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
    let names = predicates.iter().map(Predicate::column).collect::<Vec<_>>();
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

pub(super) fn partition_matches(artifact: &ParquetArtifactV1, filter: &GraphQueryFilter) -> bool {
    filter.time_range().is_none_or(|(from, to)| {
        artifact.partition_date.len() == 10
            && artifact.partition_date.as_str() >= &from[..10]
            && artifact.partition_date.as_str() <= &to[..10]
    }) && filter
        .account_or_project()
        .is_none_or(|value| artifact.partition_account == super::writer::safe_partition(value))
        && filter
            .region()
            .is_none_or(|value| artifact.partition_region == super::writer::safe_partition(value))
}

#[cfg(test)]
mod tests;
