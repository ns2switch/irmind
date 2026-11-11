//! Keep a small prefix in memory so a short order break can spill in one pass.
use super::{
    AppError, CancellationToken, EvidenceHash, Initial, Input, MappedIngestRequest, ParquetStore,
    Plan, RecordRow, StagedSource, VerifiedInput, invalid_source, source_sample,
};
use crate::parquet_store::{
    BATCH_BYTES, BATCH_ROWS, local::verify_source_unchanged, partitioning::staging::RowSpool,
};

pub(super) fn plan_source(
    store: &ParquetStore,
    request: &MappedIngestRequest<'_>,
    mut input: Input,
    initial: Initial,
    hash: EvidenceHash,
    cancel: &CancellationToken,
) -> Result<Plan, AppError> {
    let _stage = store
        .profile
        .as_ref()
        .map(|p| p.measure(crate::parquet_store::PartitionPhase::Stage));
    let sample = source_sample(&mut input.file)?;
    let mut prefix = Prefix {
        rows: Some(Vec::new()),
        bytes: 0,
        previous: None,
        spool: None,
        must_replay: false,
    };
    let (report, mapping) = match store.parse_normalized(
        request.case_id,
        VerifiedInput {
            source: &mut input.file,
            sample: &sample,
            relative_path: &input.path,
            hash: initial.1,
            hash_value: &hash,
            size: initial.2,
            cancel,
            parser: request.parser,
            precise_time: true,
            decode_budget: input.decode_budget,
        },
        &mut |row| prefix.push(row, store, request.case_id, input.budget, cancel),
    ) {
        Err(AppError::Cancelled) if prefix.must_replay && !cancel.is_cancelled() => {
            return store
                .stage_hashed_source(
                    request.case_id,
                    input,
                    request.parser,
                    request.copy_original,
                    cancel,
                    initial,
                )
                .map(|source| Plan::Sorted(Box::new(source)));
        }
        other => other?,
    };
    let Some(spool) = prefix.spool else {
        return Ok(Plan::Stream(input, hash));
    };
    let completed = spool.finish(report.accepted)?;
    verify_source_unchanged(&input.file, &initial.0, &hash)?;
    let manifest = ParquetStore::source_manifest(
        &input.path,
        &initial.0,
        initial.2,
        hash,
        request.copy_original,
    )?;
    Ok(Plan::Sorted(Box::new(StagedSource {
        mapping,
        spool: completed.file,
        source: input.file,
        manifest,
        report,
        sample_hash: irmind_app::sha256(&sample),
        normalized_hash: completed.hash,
        needs_sort: true,
        disk: completed.disk,
    })))
}

struct Prefix {
    rows: Option<Vec<RecordRow>>,
    bytes: usize,
    previous: Option<irmind_domain::StableRecordKey<'static>>,
    spool: Option<RowSpool>,
    must_replay: bool,
}

impl Prefix {
    fn push(
        &mut self,
        row: RecordRow,
        store: &ParquetStore,
        case: &irmind_domain::CaseId,
        budget: u64,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if let Some(spool) = &mut self.spool {
            return spool.push(&row);
        }
        let key = row.sort_key();
        if let Some(previous) = self.previous
            && irmind_domain::compare_record_keys(previous, key, false)
                .map_err(|_| invalid_source())?
                .is_gt()
        {
            let Some(rows) = self.rows.take() else {
                self.must_replay = true;
                return Err(AppError::Cancelled);
            };
            let mut spool = RowSpool::new(store, case, budget)?;
            for buffered in &rows {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                spool.push(buffered)?;
            }
            spool.push(&row)?;
            self.spool = Some(spool);
            return Ok(());
        }
        self.previous = Some(key);
        if let Some(rows) = &mut self.rows {
            self.bytes = self.bytes.saturating_add(
                row.estimated_bytes()
                    .saturating_mul(2)
                    .saturating_add(std::mem::size_of::<RecordRow>() * 2),
            );
            if self.bytes > BATCH_BYTES || rows.len() >= BATCH_ROWS {
                self.rows = None;
            } else {
                rows.push(row);
            }
        }
        Ok(())
    }
}
