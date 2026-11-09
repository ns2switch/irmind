//! Preserve eager stable ordering/deduplication while owning only retained rows.
use super::{AppError, EventHit};
use crate::parquet_store::time_cell::{BorrowedCell, BorrowedRows};
use arrow::{array::StringArray, record_batch::RecordBatch};
#[derive(Clone, Copy)]
enum Origin {
    Retained(usize),
    Batch(usize),
}
struct Ranked<'a> {
    key: BorrowedCell<'a>,
    origin: Origin,
}

pub(super) fn retain_batch(
    batch: &RecordBatch,
    hits: &mut Vec<EventHit>,
    limit: usize,
    newest: bool,
    precise: bool,
) -> Result<usize, AppError> {
    if batch
        .column_by_name("event")
        .and_then(|a| a.as_any().downcast_ref::<StringArray>())
        .is_none()
    {
        return Err(crate::parquet_store::invalid_source());
    }
    let bindings = BorrowedRows::new(batch)?;
    let mut ranked = hits
        .iter()
        .enumerate()
        .map(|(i, h)| Ranked {
            key: BorrowedCell::from_owned(&h.time),
            origin: Origin::Retained(i),
        })
        .collect::<Vec<_>>();
    for row in 0..batch.num_rows() {
        // Validate every ordering value, including rows outside the output limit.
        ranked.push(Ranked {
            key: bindings.at(row)?,
            origin: Origin::Batch(row),
        });
    }
    let mut error = None;
    ranked.sort_by(|a, b| match a.key.compare_borrowed_order(b.key, newest) {
        Ok(order) => order,
        Err(e) => {
            error = Some(e);
            std::cmp::Ordering::Equal
        }
    });
    if let Some(error) = error {
        return Err(error);
    }
    ranked.dedup_by(|a, b| a.key.identity() == b.key.identity());
    ranked.truncate(limit);
    let mut materialized = 0;
    let retained = ranked
        .iter()
        .map(|rank| match rank.origin {
            Origin::Retained(i) => Ok(hits[i].clone()),
            Origin::Batch(row) => {
                materialized += 1;
                EventHit::from_batch(batch, row, precise)
            }
        })
        .collect::<Result<_, _>>()?;
    drop(ranked);
    *hits = retained;
    Ok(materialized)
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
