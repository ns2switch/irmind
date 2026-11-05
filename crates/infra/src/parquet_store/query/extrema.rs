//! Shared exact count/extrema accumulation and optional batch CPU timing.
use super::super::time_cell::TimeCell;
use super::super::{AppError, ParquetProfile};
use arrow::record_batch::RecordBatch;

pub(super) fn accumulate(
    batch: &RecordBatch,
    count: &mut u64,
    first: &mut Option<TimeCell>,
    last: &mut Option<TimeCell>,
    profile: Option<&ParquetProfile>,
) -> Result<(), AppError> {
    let _aggregate = profile.map(|p| p.query_timer(super::super::profile::QueryPhase::Aggregate));
    for row in 0..batch.num_rows() {
        let at = TimeCell::from_batch(batch, row)?;
        *count += 1;
        if at.time.is_some() {
            if first
                .as_ref()
                .map(|old| at.compare(old, false))
                .transpose()?
                .is_none_or(std::cmp::Ordering::is_lt)
            {
                *first = Some(at.clone());
            }
            if last
                .as_ref()
                .map(|old| at.compare(old, false))
                .transpose()?
                .is_none_or(std::cmp::Ordering::is_gt)
            {
                *last = Some(at);
            }
        }
    }

    Ok(())
}
