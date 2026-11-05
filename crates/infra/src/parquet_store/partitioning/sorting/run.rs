use super::super::super::{
    AppError, CancellationToken, File, ParquetStore, RecordRow, invalid_source, storage,
};
use super::super::{staging::MAX_STAGED_ROW, temporary::DiskLease};
use irmind_domain::CaseId;
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};

pub(super) struct Run {
    path: tempfile::TempPath,
    hash: [u8; 32],
    bytes: u64,
    rows: usize,
    _disk: DiskLease,
}

pub(super) struct RunReader {
    reader: std::io::BufReader<File>,
    hash: Sha256,
    bytes: u64,
    rows: usize,
    expected: ([u8; 32], u64, usize),
}
impl RunReader {
    pub(super) fn new(file: File, hash: [u8; 32], bytes: u64, rows: usize) -> Self {
        Self {
            reader: std::io::BufReader::new(file),
            hash: Sha256::new(),
            bytes: 0,
            rows: 0,
            expected: (hash, bytes, rows),
        }
    }
    pub(super) fn next(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<RecordRow>, AppError> {
        self.next_encoded(cancel)
            .map(|row| row.map(|(value, _)| value))
    }

    pub(super) fn next_encoded(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<(RecordRow, Vec<u8>)>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut line = Vec::new();
        (&mut self.reader)
            .take(MAX_STAGED_ROW + 1)
            .read_until(b'\n', &mut line)
            .map_err(storage)?;
        if line.is_empty() {
            let actual: [u8; 32] = self.hash.clone().finalize().into();
            if (actual, self.bytes, self.rows) != self.expected {
                return Err(invalid_source());
            }
            return Ok(None);
        }
        self.bytes = self
            .bytes
            .checked_add(line.len() as u64)
            .ok_or_else(invalid_source)?;
        self.rows = self.rows.checked_add(1).ok_or_else(invalid_source)?;
        if line.len() as u64 > MAX_STAGED_ROW
            || line.last() != Some(&b'\n')
            || self.bytes > self.expected.1
            || self.rows > self.expected.2
        {
            return Err(invalid_source());
        }
        self.hash.update(&line);
        let value = serde_json::from_slice(&line).map_err(storage)?;
        Ok(Some((value, line)))
    }
}
impl Run {
    pub(super) fn reader(&self) -> Result<RunReader, AppError> {
        let root = self.path.parent().ok_or_else(invalid_source)?;
        let name = self.path.file_name().ok_or_else(invalid_source)?;
        let file =
            irmind_fs::open_regular_no_follow(root, std::path::Path::new(name)).map_err(storage)?;
        Ok(RunReader::new(file, self.hash, self.bytes, self.rows))
    }
}

pub(super) struct RunWriter {
    writer: Option<std::io::BufWriter<File>>,
    file: tempfile::NamedTempFile,
    hash: Sha256,
    bytes: u64,
    rows: usize,
    disk: DiskLease,
}
impl RunWriter {
    pub(super) fn new(store: &ParquetStore, case: &CaseId) -> Result<Self, AppError> {
        let file = store.create_normalized_spool(case)?;
        let writer = std::io::BufWriter::new(file.as_file().try_clone().map_err(storage)?);
        Ok(Self {
            writer: Some(writer),
            file,
            hash: Sha256::new(),
            bytes: 0,
            rows: 0,
            disk: DiskLease::new(store.profile.clone()),
        })
    }
    pub(super) fn push(&mut self, row: &RecordRow) -> Result<(), AppError> {
        let encoded = serde_json::to_vec(row).map_err(storage)?;
        let count = (encoded.len() as u64)
            .checked_add(1)
            .ok_or_else(invalid_source)?;
        if count > MAX_STAGED_ROW {
            return Err(invalid_source());
        }
        self.bytes = self.bytes.checked_add(count).ok_or_else(invalid_source)?;
        self.rows = self.rows.checked_add(1).ok_or_else(invalid_source)?;
        let writer = self.writer.as_mut().ok_or_else(invalid_source)?;
        writer.write_all(&encoded).map_err(storage)?;
        writer.write_all(b"\n").map_err(storage)?;
        self.hash.update(&encoded);
        self.hash.update(b"\n");
        self.disk.add(count)
    }
    pub(super) fn push_encoded(&mut self, line: &[u8]) -> Result<(), AppError> {
        let count = u64::try_from(line.len()).map_err(storage)?;
        if count > MAX_STAGED_ROW || line.last() != Some(&b'\n') {
            return Err(invalid_source());
        }
        self.bytes = self.bytes.checked_add(count).ok_or_else(invalid_source)?;
        self.rows = self.rows.checked_add(1).ok_or_else(invalid_source)?;
        self.writer
            .as_mut()
            .ok_or_else(invalid_source)?
            .write_all(line)
            .map_err(storage)?;
        self.hash.update(line);
        self.disk.add(count)
    }

    pub(super) fn finish(mut self) -> Result<Run, AppError> {
        self.writer
            .as_mut()
            .ok_or_else(invalid_source)?
            .flush()
            .map_err(storage)?;
        drop(self.writer.take());
        Ok(Run {
            path: self.file.into_temp_path(),
            hash: self.hash.finalize().into(),
            bytes: self.bytes,
            rows: self.rows,
            _disk: self.disk,
        })
    }
}

pub(super) fn copy_final(
    run: &Run,
    file: &mut File,
    disk: &mut DiskLease,
    cancel: &CancellationToken,
) -> Result<[u8; 32], AppError> {
    use std::io::{Seek as _, SeekFrom};
    file.set_len(0).map_err(storage)?;
    file.seek(SeekFrom::Start(0)).map_err(storage)?;
    disk.clear();
    let mut writer = std::io::BufWriter::new(file);
    let root = run.path.parent().ok_or_else(invalid_source)?;
    let mut input = irmind_fs::open_regular_no_follow(
        root,
        std::path::Path::new(run.path.file_name().ok_or_else(invalid_source)?),
    )
    .map_err(storage)?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let n = input.read(&mut buffer).map_err(storage)?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).ok_or_else(invalid_source)?;
        if bytes > run.bytes {
            return Err(invalid_source());
        }
        hash.update(&buffer[..n]);
        writer.write_all(&buffer[..n]).map_err(storage)?;
        disk.add(n as u64)?;
    }
    writer.flush().map_err(storage)?;
    let actual: [u8; 32] = hash.finalize().into();
    if actual != run.hash || bytes != run.bytes {
        return Err(invalid_source());
    }
    Ok(actual)
}
