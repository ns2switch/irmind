//! Bounded parser workers. Only the coordinator assigns signed partitions.
use super::super::super::local::{stream, verify_source_unchanged};
use super::super::super::{
    AppError, BATCH_BYTES, BATCH_ROWS, CancellationToken, File, ParquetStore, ParseReport,
    RecordRow, SourceManifestV1, StreamingEventParser, invalid_source, storage,
};
use super::super::staging::{Input, MAX_STAGED_ROW, normalized_row, source_sample};
use std::io::Write;
use std::sync::mpsc::SyncSender;

pub(in crate::parquet_store::partitioning) struct ParsedSource {
    pub(in crate::parquet_store::partitioning) source: File,
    pub(in crate::parquet_store::partitioning) manifest: SourceManifestV1,
    pub(in crate::parquet_store::partitioning) report: ParseReport,
    pub(in crate::parquet_store::partitioning) sample_hash: [u8; 32],
    pub(in crate::parquet_store::partitioning) budget: u64,
}

pub(super) struct RowBatch {
    pub(super) rows: Vec<RecordRow>,
    pub(super) hash: irmind_domain::EvidenceHash,
}

impl ParquetStore {
    pub(super) fn produce_ordered_rows(
        &self,
        mut input: Input,
        parser: &dyn StreamingEventParser,
        copied: bool,
        cancel: &CancellationToken,
        sender: &SyncSender<RowBatch>,
    ) -> Result<ParsedSource, AppError> {
        let (metadata, hash, size) =
            stream::initial_hash(&mut input.file, cancel, self.profile.as_deref())?;
        let _stage = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::super::PartitionPhase::Stage));
        let value = irmind_domain::EvidenceHash::parse(&irmind_app::hex(&hash))
            .map_err(|_| invalid_source())?;
        let sample = source_sample(&mut input.file)?;
        let mut rows = RowBuffer::new(sender, input.budget, value.clone());
        let mut offset_mode = None;
        let report = stream::parse_and_verify(
            stream::VerifiedInput {
                source: &mut input.file,
                sample: &sample,
                relative_path: &input.path,
                hash,
                hash_value: &value,
                size,
                cancel,
                parser,
                precise_time: true,
            },
            &mut |record| {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                rows.push(normalized_row(
                    &record,
                    parser,
                    &input.path,
                    &value,
                    &mut offset_mode,
                    size,
                )?)
            },
        )?;
        rows.finish()?;
        if report.accepted == 0 || report.accepted != rows.accepted {
            return Err(invalid_source());
        }
        verify_source_unchanged(&input.file, &metadata, &value)?;
        Ok(ParsedSource {
            source: input.file,
            manifest: Self::source_manifest(&input.path, &metadata, size, value, copied)?,
            report,
            sample_hash: irmind_app::sha256(&sample),
            budget: input.budget,
        })
    }
}

struct RowBuffer<'a> {
    sender: &'a SyncSender<RowBatch>,
    rows: Vec<RecordRow>,
    bytes: usize,
    encoded: u64,
    budget: u64,
    accepted: usize,
    hash: irmind_domain::EvidenceHash,
}

impl<'a> RowBuffer<'a> {
    fn new(
        sender: &'a SyncSender<RowBatch>,
        budget: u64,
        hash: irmind_domain::EvidenceHash,
    ) -> Self {
        Self {
            sender,
            rows: Vec::new(),
            bytes: 0,
            encoded: 0,
            budget,
            accepted: 0,
            hash,
        }
    }

    fn push(&mut self, row: RecordRow) -> Result<(), AppError> {
        // Preserve the existing per-row and per-source normalized-size limits
        // without allocating or writing a serialized copy of every record.
        let mut counter = EncodedSize(1);
        serde_json::to_writer(&mut counter, &row).map_err(storage)?;
        self.encoded = self
            .encoded
            .checked_add(counter.0)
            .ok_or_else(invalid_source)?;
        if self.encoded > self.budget {
            return Err(invalid_source());
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
            self.sender
                .send(RowBatch {
                    rows: std::mem::take(&mut self.rows),
                    hash: self.hash.clone(),
                })
                .map_err(|_| AppError::Cancelled)?;
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
