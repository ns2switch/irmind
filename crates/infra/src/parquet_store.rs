//! Bounded local conversion. Only artifacts returned here may enter the signed
//! manifest; query paths validate that manifest before opening a Parquet file.

use arrow::array::{ArrayRef, StringArray, UInt64Array};
use arrow::record_batch::RecordBatch;
use irmind_app::{
    AppError, CancellationToken, GraphRecord, LargeCaseStore, PreparedSource, StreamingEventParser,
};
use irmind_domain::{CaseId, EvidenceHash, ParquetArtifactV1, SourceManifestV1};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;
use std::time::{Duration, Instant};

mod compact;
mod local;
mod query;
mod scan;
mod store_bridge;
mod writer;
use writer::{
    Partition, PartitionSinks, RecordRow, StagedArtifact, batch_to_parquet, finish_parquet,
};

const READ_CHUNK: usize = 1024 * 1024;
const BATCH_ROWS: usize = 8192;
const BATCH_BYTES: usize = 8 * 1024 * 1024;

fn storage(_error: impl std::fmt::Display) -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
        irmind_app::AdapterStorageError::LocalStorageOperationFailed,
    ))
}

fn storage_phase(error: AppError, phase: irmind_app::AdapterStorageError) -> AppError {
    match error {
        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::LocalStorageOperationFailed,
        )) => AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(phase)),
        other => other,
    }
}

fn invalid_source() -> AppError {
    AppError::Policy("source path or content is invalid".into())
}

pub struct ParquetStore {
    root: PathBuf,
    finish_lock: std::sync::Mutex<()>,
    profile: Option<Arc<ParquetProfile>>,
}

#[derive(Default)]
pub(crate) struct ParquetProfile {
    hash: AtomicU64,
    conversion: AtomicU64,
    row: AtomicU64,
    parquet: AtomicU64,
    query_verify: AtomicU64,
    query_scan: AtomicU64,
}

impl ParquetProfile {
    fn nanos(duration: Duration) -> u64 {
        u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
    }

    fn record_hash(&self, duration: Duration) {
        self.hash
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    fn record_conversion(&self, duration: Duration) {
        self.conversion
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    fn record_row(&self, duration: Duration) {
        self.row.fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    fn record_parquet(&self, duration: Duration) {
        self.parquet
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    fn record_query_verify(&self, duration: Duration) {
        self.query_verify
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    fn record_query_scan(&self, duration: Duration) {
        self.query_scan
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> [Duration; 6] {
        [
            Duration::from_nanos(self.hash.load(Ordering::Relaxed)),
            Duration::from_nanos(self.conversion.load(Ordering::Relaxed)),
            Duration::from_nanos(self.row.load(Ordering::Relaxed)),
            Duration::from_nanos(self.parquet.load(Ordering::Relaxed)),
            Duration::from_nanos(self.query_verify.load(Ordering::Relaxed)),
            Duration::from_nanos(self.query_scan.load(Ordering::Relaxed)),
        ]
    }
}

impl ParquetStore {
    pub fn open(data_root: &Path) -> Result<Self, AppError> {
        #[cfg(windows)]
        let data_root = &fs::canonicalize(data_root).map_err(storage)?;
        let root = data_root.join("parquet");
        fs::create_dir_all(&root).map_err(storage)?;
        irmind_fs::private_dir(&root).map_err(storage)?;
        Ok(Self {
            root,
            finish_lock: std::sync::Mutex::new(()),
            profile: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn attach_profile(&mut self, profile: Arc<ParquetProfile>) {
        self.profile = Some(profile);
    }

    pub(crate) fn case_dir(&self, id: &CaseId) -> Result<PathBuf, AppError> {
        let dir = self.root.join(id.as_str());
        fs::create_dir_all(&dir).map_err(storage)?;
        irmind_fs::private_dir(&dir).map_err(storage)?;
        Ok(dir)
    }

    fn open_source(source_root: &Path, relative: &str) -> Result<File, AppError> {
        let check = SourceManifestV1 {
            source: relative.into(),
            size: 0,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: EvidenceHash::parse(&"0".repeat(64)).map_err(|_| invalid_source())?,
            copied: false,
        };
        check.validate().map_err(|_| invalid_source())?;
        if relative.contains("://") {
            return Err(invalid_source());
        }
        irmind_fs::open_regular_no_follow(source_root, Path::new(relative)).map_err(storage)
    }

    fn source_manifest(
        relative_path: &str,
        metadata: &fs::Metadata,
        size: u64,
        sha256: EvidenceHash,
        copied: bool,
    ) -> Result<SourceManifestV1, AppError> {
        let modified_unix_seconds = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|delta| delta.as_secs());
        let manifest = SourceManifestV1 {
            source: relative_path.into(),
            size,
            modified_unix_seconds,
            version: None,
            provider_checksum: None,
            sha256,
            copied,
        };
        manifest.validate().map_err(|_| invalid_source())?;
        Ok(manifest)
    }

    fn hash_reader(
        reader: &mut File,
        cancel: &CancellationToken,
    ) -> Result<([u8; 32], u64), AppError> {
        reader.seek(SeekFrom::Start(0)).map_err(storage)?;
        let mut hasher = Sha256::new();
        let mut bytes = 0u64;
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let count = reader.read(&mut chunk).map_err(storage)?;
            if count == 0 {
                break;
            }
            hasher.update(&chunk[..count]);
            bytes = bytes.checked_add(count as u64).ok_or_else(invalid_source)?;
        }
        Ok((hasher.finalize().into(), bytes))
    }

    fn finish_artifacts(
        &self,
        id: &CaseId,
        staged: Vec<StagedArtifact>,
    ) -> Result<Vec<ParquetArtifactV1>, AppError> {
        let _finish_lock = self.finish_lock.lock().map_err(storage)?;
        let case_dir = self.case_dir(id)?;
        let mut artifacts = Vec::with_capacity(staged.len());
        for artifact in staged {
            artifact.manifest.validate().map_err(|_| invalid_source())?;
            let target = case_dir.join(&artifact.manifest.path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(storage)?;
                irmind_fs::private_dir(parent).map_err(storage)?;
            }
            if target.exists() {
                let mut file = irmind_fs::open_regular_no_follow(
                    &case_dir,
                    Path::new(&artifact.manifest.path),
                )
                .map_err(storage)?;
                let existing = Self::hash_reader(&mut file, &CancellationToken::new())?;
                if existing.0 != parse_hash(&artifact.manifest.sha256)? {
                    return Err(AppError::EvidenceMismatch(artifact.manifest.path.clone()));
                }
                fs::remove_file(&artifact.temporary).map_err(storage)?;
            } else {
                irmind_fs::durable_rename(&artifact.temporary, &target).map_err(storage)?;
                irmind_fs::private_file(&target).map_err(storage)?;
                if let Some(parent) = target.parent() {
                    irmind_fs::sync_directory(parent).map_err(storage)?;
                }
            }
            artifacts.push(artifact.manifest.clone());
        }
        Ok(artifacts)
    }

    fn copy_source(
        &self,
        id: &CaseId,
        source: &mut File,
        expected: &EvidenceHash,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let _finish_lock = self.finish_lock.lock().map_err(storage)?;
        let dir = self.case_dir(id)?.join("originals");
        fs::create_dir_all(&dir).map_err(storage)?;
        irmind_fs::private_dir(&dir).map_err(storage)?;
        let target = dir.join(expected.as_str());
        if target.exists() {
            let mut file = irmind_fs::open_regular_no_follow(
                &self.case_dir(id)?,
                Path::new(&format!("originals/{}", expected.as_str())),
            )
            .map_err(storage)?;
            let (hash, _) = Self::hash_reader(&mut file, cancel)?;
            if hash != parse_hash(expected)? {
                return Err(AppError::EvidenceMismatch(expected.as_str().into()));
            }
            return Ok(());
        }
        source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let temporary = dir.join(format!(
            ".{}.{}.tmp",
            expected.as_str(),
            rand::random::<u64>()
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut output = options.open(&temporary).map_err(storage)?;
            irmind_fs::private_file(&temporary).map_err(storage)?;
            let mut digest = Sha256::new();
            let mut buffer = vec![0u8; READ_CHUNK];
            loop {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let count = source.read(&mut buffer).map_err(storage)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
                output.write_all(&buffer[..count]).map_err(storage)?;
            }
            if <[u8; 32]>::from(digest.finalize()) != parse_hash(expected)? {
                return Err(AppError::EvidenceMismatch(expected.as_str().into()));
            }
            output.sync_all().map_err(storage)?;
            drop(output);
            irmind_fs::durable_rename(&temporary, &target).map_err(storage)?;
            irmind_fs::sync_directory(&dir).map_err(storage)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new(parent: &Path) -> Result<Self, AppError> {
        let path = parent.join(format!(".verify-{}", rand::random::<u128>()));
        fs::create_dir(&path).map_err(storage)?;
        irmind_fs::private_dir(&path).map_err(storage)?;
        Ok(Self { path })
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn parse_hash(value: &EvidenceHash) -> Result<[u8; 32], AppError> {
    hex::decode(value.as_str())
        .map_err(storage)?
        .try_into()
        .map_err(|_| invalid_source())
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn drain(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        let mut bytes = vec![0u8; READ_CHUNK];
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if self.read(&mut bytes).map_err(storage)? == 0 {
                return Ok(());
            }
        }
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(output)?;
        self.hasher.update(&output[..count]);
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("source size overflow"))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests;
