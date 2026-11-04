use super::{
    AppError, CancellationToken, Instant, ParquetArtifact, ParquetStore, Path, ScanSpec, storage,
};
use sha2::{Digest, Sha256};
use std::io::{Read as _, Seek as _, SeekFrom};
impl ParquetStore {
    pub(super) fn verify_for_scan(
        &self,
        case_dir: &Path,
        artifact: &ParquetArtifact,
        spec: &ScanSpec<'_>,
    ) -> Result<Option<std::fs::File>, AppError> {
        if spec.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if Instant::now() >= spec.deadline {
            return Ok(None);
        }
        artifact
            .validate()
            .map_err(|_| crate::parquet_store::invalid_source())?;
        let verify_started = Instant::now();
        let mut file = irmind_fs::open_regular_no_follow(case_dir, Path::new(&artifact.path()))
            .map_err(storage)?;
        let Some((digest, size)) = hash_until_deadline(&mut file, spec.cancel, spec.deadline)?
        else {
            return Ok(None);
        };
        if size != artifact.size() || digest != crate::parquet_store::parse_hash(artifact.sha256())?
        {
            return Err(AppError::EvidenceMismatch(
                artifact.sha256().as_str().into(),
            ));
        }
        file.seek(SeekFrom::Start(0)).map_err(storage)?;
        if let Some(profile) = &self.profile {
            profile.record_query_verify(verify_started.elapsed());
        }
        Ok(Some(file))
    }
}
fn hash_until_deadline(
    file: &mut std::fs::File,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Option<([u8; 32], u64)>, AppError> {
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let count = file.read(&mut buffer).map_err(storage)?;
        if count == 0 {
            return Ok(Some((hasher.finalize().into(), size)));
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| AppError::Policy("Parquet size overflow".into()))?;
        hasher.update(&buffer[..count]);
    }
}
