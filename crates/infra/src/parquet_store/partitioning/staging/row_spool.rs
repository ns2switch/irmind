use super::{
    AppError, CaseId, DiskLease, MAX_STAGED_ROW, ParquetStore, RecordRow, invalid_source, no_space,
    storage,
};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Seek as _, Write as _};

pub(in crate::parquet_store::partitioning) struct RowSpool {
    writer: BufWriter<tempfile::NamedTempFile>,
    disk: DiskLease,
    hash: Sha256,
    bytes: u64,
    budget: u64,
    rows: usize,
}

pub(in crate::parquet_store::partitioning) struct CompletedSpool {
    pub(in crate::parquet_store::partitioning) file: tempfile::NamedTempFile,
    pub(in crate::parquet_store::partitioning) hash: [u8; 32],
    pub(in crate::parquet_store::partitioning) disk: DiskLease,
}

impl RowSpool {
    pub(in crate::parquet_store::partitioning) fn new(
        store: &ParquetStore,
        case: &CaseId,
        budget: u64,
    ) -> Result<Self, AppError> {
        let file = store.create_normalized_spool(case)?;
        if let Some(profile) = &store.profile {
            profile.record_staged_source();
        }
        Ok(Self {
            writer: BufWriter::new(file),
            disk: DiskLease::new(store.profile.clone()),
            hash: Sha256::new(),
            bytes: 0,
            budget,
            rows: 0,
        })
    }

    pub(in crate::parquet_store::partitioning) fn push(
        &mut self,
        row: &RecordRow,
    ) -> Result<(), AppError> {
        let encoded = serde_json::to_vec(row).map_err(storage)?;
        let count = u64::try_from(encoded.len()).map_err(storage)? + 1;
        self.bytes = self.bytes.checked_add(count).ok_or_else(no_space)?;
        if count > MAX_STAGED_ROW || self.bytes > self.budget {
            return Err(no_space());
        }
        self.hash.update(&encoded);
        self.hash.update(b"\n");
        self.rows = self.rows.checked_add(1).ok_or_else(invalid_source)?;
        self.writer.write_all(&encoded).map_err(storage)?;
        self.writer.write_all(b"\n").map_err(storage)?;
        self.disk.add(count)
    }

    pub(in crate::parquet_store::partitioning) fn finish(
        mut self,
        accepted: usize,
    ) -> Result<CompletedSpool, AppError> {
        self.writer.flush().map_err(storage)?;
        if accepted == 0 || accepted != self.rows {
            return Err(invalid_source());
        }
        let mut file = self.writer.into_inner().map_err(storage)?;
        file.as_file_mut().rewind().map_err(storage)?;
        Ok(CompletedSpool {
            file,
            hash: self.hash.finalize().into(),
            disk: self.disk,
        })
    }
}
