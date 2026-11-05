//! Time bounds come only from statistics inside hash-verified Parquet files.
use super::{AppError, Instant, MAX_QUERY_FILES, ParquetArtifact, ParquetStore, ScanSpec, storage};
use irmind_app::IndexedInstant;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::statistics::Statistics;
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::parquet_store) enum TimeBound {
    Unbounded,
    Known(Option<IndexedInstant>),
}

impl TimeBound {
    pub(in crate::parquet_store) fn cannot_beat(
        self,
        cutoff: Option<IndexedInstant>,
        newest: bool,
    ) -> bool {
        match (self, cutoff) {
            (Self::Known(None), Some(_)) => true,
            (Self::Known(Some(bound)), Some(cutoff)) => {
                if newest {
                    bound < cutoff
                } else {
                    bound > cutoff
                }
            }
            // Equal instants must still be read for stable source/offset ties.
            _ => false,
        }
    }

    pub(super) fn compare(self, other: Self, newest: bool) -> Ordering {
        match (self, other) {
            (Self::Unbounded, Self::Unbounded) | (Self::Known(None), Self::Known(None)) => {
                Ordering::Equal
            }
            (Self::Unbounded, _) | (Self::Known(Some(_)), Self::Known(None)) => Ordering::Less,
            (_, Self::Unbounded) | (Self::Known(None), Self::Known(Some(_))) => Ordering::Greater,
            (Self::Known(Some(a)), Self::Known(Some(b))) => {
                if newest {
                    b.cmp(&a)
                } else {
                    a.cmp(&b)
                }
            }
        }
    }
}

impl ParquetStore {
    pub(in crate::parquet_store) fn time_ordered_artifacts<'a>(
        &self,
        spec: &ScanSpec<'a>,
        newest: bool,
        names: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<(TimeBound, &'a ParquetArtifact)>, AppError> {
        let selected = spec
            .artifacts
            .iter()
            .filter(|a| {
                super::super::format::same_family(a.schema_version(), spec.schema)
                    && super::partition_matches(a, spec.filter)
            })
            .collect::<Vec<_>>();
        if selected.len() > MAX_QUERY_FILES {
            return Err(AppError::Policy(
                "too many Parquet partitions; narrow the query".into(),
            ));
        }
        let dir = self.case_dir(spec.id)?;
        let mut ordered = Vec::with_capacity(selected.len());
        for group in selected.chunks(4) {
            let bounds = std::thread::scope(|scope| {
                let workers = group
                    .iter()
                    .map(|artifact| {
                        let dir = &dir;
                        let artifact = *artifact;
                        scope.spawn(move || {
                            let file = self
                                .verify_for_scan(dir, artifact, spec)?
                                .ok_or_else(deadline_error)?;
                            let builder =
                                ParquetRecordBatchReaderBuilder::try_new(file).map_err(storage)?;
                            super::super::format::validate_schema(
                                artifact,
                                builder.schema().as_ref(),
                            )?;
                            let index = builder.schema().index_of("event_time").map_err(storage)?;
                            Ok::<_, AppError>((
                                file_bound(builder.metadata(), index, newest),
                                artifact,
                            ))
                        })
                    })
                    .collect::<Vec<_>>();
                // All workers finish before an error is returned.
                let results = workers
                    .into_iter()
                    .map(|w| w.join().map_err(|_| super::super::invalid_source())?)
                    .collect::<Vec<_>>();
                results.into_iter().collect::<Result<Vec<_>, _>>()
            })?;
            ordered.extend(bounds);
            if Instant::now() >= spec.deadline {
                return Err(deadline_error());
            }
        }
        ordered.sort_by(|(a, fa), (b, fb)| {
            a.compare(*b, newest)
                .then_with(|| first_source(fa, names).cmp(&first_source(fb, names)))
                .then_with(|| fa.path().cmp(fb.path()))
        });
        Ok(ordered)
    }
}

fn first_source<'a>(
    artifact: &'a ParquetArtifact,
    names: &'a std::collections::BTreeMap<String, String>,
) -> Option<(&'a str, &'a str)> {
    artifact
        .source_hashes()
        .iter()
        .map(|h| {
            (
                names.get(h.as_str()).map_or(h.as_str(), String::as_str),
                h.as_str(),
            )
        })
        .min()
}

fn file_bound(metadata: &ParquetMetaData, index: usize, newest: bool) -> TimeBound {
    let mut bound = TimeBound::Known(None);
    for group in metadata.row_groups() {
        if group.num_rows() == 0 {
            continue;
        }
        let Some(stats) = group.column(index).statistics() else {
            return TimeBound::Unbounded;
        };
        let current = statistic_bound(stats, group.num_rows(), newest);
        if current == TimeBound::Unbounded {
            return current;
        }
        if current.compare(bound, newest).is_lt() {
            bound = current;
        }
    }
    bound
}

pub(super) fn statistic_bound(stats: &Statistics, rows: i64, newest: bool) -> TimeBound {
    if stats
        .null_count_opt()
        .is_some_and(|n| u64::try_from(rows) == Ok(n))
    {
        return TimeBound::Known(None);
    }
    if !(if newest {
        stats.max_is_exact()
    } else {
        stats.min_is_exact()
    }) {
        return TimeBound::Unbounded;
    }
    let instant = match stats {
        Statistics::Int64(v) => {
            let value = if newest { v.max_opt() } else { v.min_opt() };
            value.and_then(|&micros| IndexedInstant::new(micros, if newest { 999 } else { 0 }).ok())
        }
        Statistics::ByteArray(_) => {
            let value = if newest {
                stats.max_bytes_opt()
            } else {
                stats.min_bytes_opt()
            };
            if value == Some(b"") {
                return if stats.max_bytes_opt() == Some(b"") {
                    TimeBound::Known(None)
                } else {
                    TimeBound::Unbounded
                };
            }
            value
                .and_then(|v| std::str::from_utf8(v).ok())
                .and_then(|v| irmind_domain::UtcTimestamp::parse(v).ok())
                .and_then(|v| v.unix_seconds().checked_mul(1_000_000))
                .and_then(|v| IndexedInstant::new(v, 0).ok())
        }
        _ => None,
    };
    instant.map_or(TimeBound::Unbounded, |value| TimeBound::Known(Some(value)))
}

fn deadline_error() -> AppError {
    AppError::Policy("Parquet query exceeded 10-second budget".into())
}

#[cfg(test)]
mod tests;
