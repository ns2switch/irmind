//! Stream a projected event artifact in physical row order.
use super::{SigmaEvaluation, invalid};
use arrow_array::{Array, StringArray};
use irmind_app::{
    AppError, CancellationToken, decode_common_event,
    v10_proofs::{SigmaRuleKeyV1, SigmaRunStatusV1},
};
use irmind_domain::CommonEventV1;
use parquet::{
    arrow::{ProjectionMask, arrow_reader::ParquetRecordBatchReaderBuilder},
    file::reader::ChunkReader,
};
use std::{ops::Range, time::Instant};

impl SigmaEvaluation<'_> {
    /// The caller must pin the source scope and authenticate the file and its
    /// mapping generation. The returned index is the physical artifact row.
    pub fn scan_authenticated(
        &mut self,
        reader: impl ChunkReader + 'static,
        time: Range<i64>,
        deadline: Instant,
        cancel: &CancellationToken,
        mut report: impl FnMut(u64, &CommonEventV1, &SigmaRuleKeyV1) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        if time.is_empty() {
            return Err(invalid());
        }
        if self.status != SigmaRunStatusV1::Complete || self.stop(deadline, cancel) {
            return Ok(());
        }
        let builder = ParquetRecordBatchReaderBuilder::try_new(reader).map_err(|_| invalid())?;
        let mut columns = vec![
            builder
                .schema()
                .index_of("common_payload")
                .map_err(|_| invalid())?,
        ];
        if self.programs.needs_original() {
            columns.push(builder.schema().index_of("text").map_err(|_| invalid())?);
        }
        let projection = ProjectionMask::roots(builder.parquet_schema(), columns);
        let mut reader = builder
            .with_projection(projection)
            .with_batch_size(1024)
            .build()
            .map_err(|_| invalid())?;
        let mut physical = 0u64;
        while !self.stop(deadline, cancel) {
            let Some(batch) = reader.next() else {
                break;
            };
            let batch = batch.map_err(|_| invalid())?;
            let column = |name: &str| {
                batch
                    .column_by_name(name)
                    .and_then(|array| array.as_any().downcast_ref::<StringArray>())
                    .ok_or_else(invalid)
            };
            let common = column("common_payload")?;
            let original = self
                .programs
                .needs_original()
                .then(|| column("text"))
                .transpose()?;
            for index in 0..batch.num_rows() {
                if self.stop(deadline, cancel) || !self.charge(1) {
                    return Ok(());
                }
                let row = physical;
                physical = physical.checked_add(1).ok_or_else(invalid)?;
                if common.is_null(index) || original.is_some_and(|value| value.is_null(index)) {
                    return Err(invalid());
                }
                let event = decode_common_event(common.value(index))?;
                if !event
                    .timestamp()
                    .is_some_and(|value| time.contains(&value.instant().unix_micros()))
                {
                    continue;
                }
                if !self.row(
                    &event,
                    original.map(|value| value.value(index)),
                    cancel,
                    |key| report(row, &event, key),
                )? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn stop(&mut self, deadline: Instant, cancel: &CancellationToken) -> bool {
        if cancel.is_cancelled() {
            self.status = SigmaRunStatusV1::Cancelled;
            true
        } else if Instant::now() >= deadline {
            self.status = SigmaRunStatusV1::TimeLimit;
            true
        } else {
            false
        }
    }
}
