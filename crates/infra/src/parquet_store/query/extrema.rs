//! Shared exact count/extrema accumulation and optional batch CPU timing.
use super::super::time_cell::{BorrowedCell, BorrowedRows, TimeCell};
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
    let rows = BorrowedRows::new(batch)?;
    let (mut batch_first, mut batch_last) = (None::<BorrowedCell<'_>>, None::<BorrowedCell<'_>>);
    for row in 0..batch.num_rows() {
        let at = rows.at(row)?;
        *count += 1;
        if at.has_time() {
            if batch_first
                .map(|old| at.compare_borrowed(old))
                .transpose()?
                .is_none_or(std::cmp::Ordering::is_lt)
            {
                batch_first = Some(at);
            }
            if batch_last
                .map(|old| at.compare_borrowed(old))
                .transpose()?
                .is_none_or(std::cmp::Ordering::is_gt)
            {
                batch_last = Some(at);
            }
        }
    }
    if let Some(at) = batch_first
        && first
            .as_ref()
            .map(|old| at.compare(old, false))
            .transpose()?
            .is_none_or(std::cmp::Ordering::is_lt)
    {
        *first = Some(at.to_owned());
    }
    if let Some(at) = batch_last
        && last
            .as_ref()
            .map(|old| at.compare(old, false))
            .transpose()?
            .is_none_or(std::cmp::Ordering::is_gt)
    {
        *last = Some(at.to_owned());
    }

    Ok(())
}

#[cfg(test)]
mod tests;
