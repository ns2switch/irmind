//! Bounded parser workers. Only the coordinator assigns signed partitions.
use super::super::super::local::{stream, verify_source_unchanged};
use super::super::super::{
    AppError, BATCH_BYTES, BATCH_ROWS, CancellationToken, File, ParquetStore, ParseReport,
    RecordRow, SourceManifestV1, invalid_source, storage,
};
use super::super::staging::StagedSource;
use super::super::staging::{Input, MAX_STAGED_ROW, no_space, normalized_row, source_sample};
use irmind_app::LocalBatchRequest;
use std::io::{Seek as _, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Duration;

pub(in crate::parquet_store::partitioning) struct ParsedSource {
    pub(in crate::parquet_store::partitioning) source: File,
    pub(in crate::parquet_store::partitioning) manifest: SourceManifestV1,
    pub(in crate::parquet_store::partitioning) report: Option<ParseReport>,
    pub(in crate::parquet_store::partitioning) initial: Option<(std::fs::Metadata, [u8; 32], u64)>,
    pub(in crate::parquet_store::partitioning) sample_hash: [u8; 32],
    pub(in crate::parquet_store::partitioning) budget: u64,
}

pub(super) enum ProducedSource {
    Ordered(ParsedSource),
    Disordered(StagedSource),
}

impl ParsedSource {
    fn prepared(
        self,
        store: &ParquetStore,
        request: &LocalBatchRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<ProducedSource, AppError> {
        if self.report.is_some() {
            return Ok(ProducedSource::Ordered(self));
        }
        let mut source = self.source;
        source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let input = Input {
            file: source,
            path: self.manifest.source,
            budget: self.budget,
        };
        let initial = self.initial.ok_or_else(invalid_source)?;
        let staged = store.stage_hashed_source(
            request.case_id,
            input,
            request.parser,
            request.copy_original,
            cancel,
            initial,
        )?;
        Ok(ProducedSource::Disordered(staged))
    }
}

pub(super) struct RowBatch {
    pub(super) rows: Vec<RecordRow>,
    pub(super) hash: irmind_domain::EvidenceHash,
}

impl ParquetStore {
    pub(super) fn produce_ordered_rows(
        &self,
        mut input: Input,
        request: &LocalBatchRequest<'_>,
        cancel: &CancellationToken,
        sender: &SyncSender<RowBatch>,
        restart: &AtomicBool,
        start: super::scheduling::Start,
    ) -> Result<ProducedSource, AppError> {
        let copied = request.copy_original;
        let (metadata, hash, size) =
            stream::initial_hash(&mut input.file, cancel, self.profile.as_deref())?;
        start.wait(cancel)?;
        let stage = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::super::PartitionPhase::Stage));
        let value = irmind_domain::EvidenceHash::parse(&irmind_app::hex(&hash))
            .map_err(|_| invalid_source())?;
        let sample = source_sample(&mut input.file)?;
        let mut rows = RowBuffer::new(sender, input.budget, value.clone(), cancel, restart);
        let mut offset_mode = None;
        let mut stopped_for_restart = false;
        let result = stream::parse_and_verify(
            stream::VerifiedInput {
                source: &mut input.file,
                sample: &sample,
                relative_path: &input.path,
                hash,
                hash_value: &value,
                size,
                cancel,
                parser: request.parser,
                precise_time: true,
            },
            &mut |record| {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                if restart.load(Ordering::Acquire) {
                    stopped_for_restart = true;
                    return Err(AppError::Cancelled);
                }
                let result = rows.push(normalized_row(
                    &record,
                    request.parser,
                    &input.path,
                    &value,
                    &mut offset_mode,
                    size,
                )?);
                if rows.disordered {
                    restart.store(true, Ordering::Release);
                }
                if result
                    .as_ref()
                    .is_err_and(|e| matches!(e, AppError::Cancelled))
                    && restart.load(Ordering::Acquire)
                    && !cancel.is_cancelled()
                {
                    stopped_for_restart = true;
                }
                result
            },
        )
        .and_then(|report| {
            let finished = rows.finish();
            if finished.is_err() && restart.load(Ordering::Acquire) && !cancel.is_cancelled() {
                stopped_for_restart = true;
            }
            finished?;
            if report.accepted == 0 || report.accepted != rows.accepted {
                return Err(invalid_source());
            }
            verify_source_unchanged(&input.file, &metadata, &value)?;
            Ok(report)
        });
        let report = completed_report(result, stopped_for_restart, cancel)?;
        drop(rows);
        drop(stage);
        ParsedSource {
            source: input.file,
            manifest: Self::source_manifest(&input.path, &metadata, size, value, copied)?,
            report,
            sample_hash: irmind_app::sha256(&sample),
            budget: input.budget,
            initial: Some((metadata, hash, size)),
        }
        .prepared(self, request, cancel)
    }
}

fn completed_report(
    result: Result<ParseReport, AppError>,
    stopped_for_restart: bool,
    cancel: &CancellationToken,
) -> Result<Option<ParseReport>, AppError> {
    match result {
        Ok(report) => Ok(Some(report)),
        Err(AppError::Cancelled) if stopped_for_restart && !cancel.is_cancelled() => Ok(None),
        Err(error) => Err(error),
    }
}

struct RowBuffer<'a> {
    sender: &'a SyncSender<RowBatch>,
    cancel: &'a CancellationToken,
    restart: &'a AtomicBool,
    rows: Vec<RecordRow>,
    bytes: usize,
    encoded: u64,
    budget: u64,
    accepted: usize,
    previous: Option<irmind_domain::StableRecordKey<'static>>,
    disordered: bool,
    hash: irmind_domain::EvidenceHash,
}

impl<'a> RowBuffer<'a> {
    fn new(
        sender: &'a SyncSender<RowBatch>,
        budget: u64,
        hash: irmind_domain::EvidenceHash,
        cancel: &'a CancellationToken,
        restart: &'a AtomicBool,
    ) -> Self {
        Self {
            sender,
            cancel,
            restart,
            rows: Vec::new(),
            bytes: 0,
            encoded: 0,
            budget,
            accepted: 0,
            previous: None,
            disordered: false,
            hash,
        }
    }

    fn push(&mut self, row: RecordRow) -> Result<(), AppError> {
        let key = row.sort_key();
        if let Some(old) = self.previous
            && irmind_domain::compare_record_keys(old, key, false)
                .map_err(|_| invalid_source())?
                .is_gt()
        {
            self.disordered = true;
            return Err(AppError::Cancelled);
        }
        self.previous = Some(key);
        // Preserve the existing per-row and per-source normalized-size limits
        // without allocating or writing a serialized copy of every record.
        let mut counter = EncodedSize(1);
        serde_json::to_writer(&mut counter, &row).map_err(|_| no_space())?;
        self.encoded = self.encoded.checked_add(counter.0).ok_or_else(no_space)?;
        if self.encoded > self.budget {
            return Err(no_space());
        }
        self.accepted = self.accepted.checked_add(1).ok_or_else(invalid_source)?;
        self.bytes = self.bytes.saturating_add(row.estimated_bytes());
        self.rows.push(row);
        if self.bytes >= BATCH_BYTES || self.rows.len() >= BATCH_ROWS {
            self.finish()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), AppError> {
        if !self.rows.is_empty() {
            let mut batch = RowBatch {
                rows: std::mem::take(&mut self.rows),
                hash: self.hash.clone(),
            };
            loop {
                if self.cancel.is_cancelled() || self.restart.load(Ordering::Acquire) {
                    return Err(AppError::Cancelled);
                }
                match self.sender.try_send(batch) {
                    Ok(()) => break,
                    Err(TrySendError::Disconnected(_)) => return Err(AppError::Cancelled),
                    Err(TrySendError::Full(value)) => {
                        batch = value;
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        self.bytes = 0;
        Ok(())
    }
}

struct EncodedSize(u64);
impl Write for EncodedSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len() as u64);
        if self.0 > MAX_STAGED_ROW {
            return Err(std::io::Error::other(
                "normalized record size limit exceeded",
            ));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_an_internally_initiated_stop_can_restart_a_source() {
        let cancel = CancellationToken::new();
        assert!(matches!(
            completed_report(Err(AppError::Cancelled), false, &cancel),
            Err(AppError::Cancelled)
        ));
        assert!(
            completed_report(Err(AppError::Cancelled), true, &cancel)
                .unwrap()
                .is_none()
        );
        cancel.cancel();
        assert!(matches!(
            completed_report(Err(AppError::Cancelled), true, &cancel),
            Err(AppError::Cancelled)
        ));
    }

    #[test]
    fn direct_rows_keep_the_existing_normalized_size_limits_and_error() {
        let mut counter = EncodedSize(MAX_STAGED_ROW);
        assert!(counter.write_all(b"x").is_err());
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let hash = irmind_domain::EvidenceHash::parse(&"a".repeat(64)).unwrap();
        let row = RecordRow::from_partitioned(
            &irmind_app::IndexedGraphRecord {
                record: irmind_app::GraphRecord {
                    index: 0,
                    at: String::new(),
                    event: "Read".into(),
                    text: "{}".into(),
                    entities: vec![],
                    relations: vec![],
                },
                time: None,
                source_offset: None,
            },
            &hash,
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let restart = AtomicBool::new(false);
        let mut buffer = RowBuffer::new(&sender, 0, hash, &cancel, &restart);
        assert!(matches!(
            buffer.push(row),
            Err(AppError::Fixed(
                irmind_app::FixedAppError::StorageNormalizedStagingSpace
            ))
        ));
        assert!(receiver.try_recv().is_err());
    }
}
