use super::{
    AppError, CancellationToken, CaseId, EvidenceHash, ParquetStore, invalid_source, storage,
};
use irmind_app::source_queries::{
    QUERY_MAX_BYTES, SourceQueryError, SourceQueryResultV1, verify_query_capture,
};
use irmind_app::{LargeCaseStore, MappedIngestRequest, PreparedMappedGroup, PreparedMappedIngest};
use irmind_domain::SourceReferenceV1;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub(super) struct CaptureOrigin {
    pub(super) case: CaseId,
    pub(super) hash: EvidenceHash,
    pub(super) reference: SourceReferenceV1,
}

impl CaptureOrigin {
    pub(super) fn reference(
        &self,
        case: &CaseId,
        logical: &str,
        hash: [u8; 32],
    ) -> Result<SourceReferenceV1, AppError> {
        if *case != self.case
            || self.reference.reference() != logical
            || super::parse_hash(&self.hash)? != hash
        {
            return Err(invalid_source());
        }
        Ok(self.reference.clone())
    }
}

impl ParquetStore {
    pub(super) fn with_capture_origin(&self, origin: CaptureOrigin) -> Self {
        Self {
            root: self.root.clone(),
            finish_lock: self.finish_lock.clone(),
            workers: self.workers.clone(),
            profile: self.profile.clone(),
            mapping_catalog: self.mapping_catalog.clone(),
            capture_origin: Some(origin),
        }
    }

    pub(super) fn prepare_query_capture(
        &self,
        request: &MappedIngestRequest<'_>,
        result: &SourceQueryResultV1,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PreparedMappedIngest>, AppError> {
        request.validate()?;
        let [source] = request.relative_paths else {
            return Err(invalid_source());
        };
        let reference = result.source_reference()?;
        let (digest, bytes) = result.capture_identity();
        let hash = EvidenceHash::parse(digest).map_err(|_| invalid_source())?;
        let root = self.owned_case_path(request.case_id);
        let spool = root.join("spool");
        if result.case_id() != request.case_id.as_str()
            || request.source_root != spool
            || !request.copy_original
            || !source.starts_with("irmind-object-")
            || Path::new(source).components().count() != 1
            || request.parser.logical_source(source) != reference.reference()
            || !result.matches_decoder(request.parser.identity_for_source(source)?)
        {
            return Err(invalid_source());
        }
        check_directory(&root)?;
        check_directory(&spool)?;
        let file = open_single_link(&spool, source, bytes, cancel)?;
        let staged = self.stage_query_capture(request.case_id, file, result, cancel)?;
        let relative = staged
            .path()
            .file_name()
            .and_then(|part| part.to_str())
            .ok_or_else(invalid_source)?
            .to_owned();
        let paths = [relative];
        if request.parser.logical_source(&paths[0]) != reference.reference()
            || !result.matches_decoder(request.parser.identity_for_source(&paths[0])?)
        {
            return Err(invalid_source());
        }
        let scoped = self.with_capture_origin(CaptureOrigin {
            case: request.case_id.clone(),
            hash: hash.clone(),
            reference,
        });
        let inner = scoped
            .prepare_mapped_ingest(
                MappedIngestRequest {
                    relative_paths: &paths,
                    copy_original: false,
                    ..*request
                },
                cancel,
            )?
            .ok_or(SourceQueryError::Unavailable)?;
        let mut metadata = inner.metadata().clone();
        let [source] = metadata.sources.as_mut_slice() else {
            return Err(invalid_source());
        };
        if source.manifest.sha256 != hash
            || source.manifest.size != bytes
            || !result.matches_rows(source.decoded.records(), source.report.rejected)
            || metadata
                .projections
                .iter()
                .any(|projection| !result.matches_mapping(projection.mapping()))
        {
            return Err(invalid_source());
        }
        source.manifest.source = result.capture_path();
        source.manifest.copied = true;
        source.manifest.modified_unix_seconds = None;
        Ok(Box::new(PreparedCapture {
            inner,
            metadata,
            staged: Some(staged),
            target: root.join(result.capture_path()),
            hash,
            bytes,
            published: false,
        }))
    }

    fn stage_query_capture(
        &self,
        case: &CaseId,
        mut input: File,
        result: &SourceQueryResultV1,
        cancel: &CancellationToken,
    ) -> Result<tempfile::NamedTempFile, AppError> {
        let (_, bytes) = result.capture_identity();
        let mut staged = self.create_object_spool(case, bytes)?;
        let mut buffer = vec![0; 64 * 1024];
        let mut remaining = bytes;
        while remaining > 0 {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let length = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| invalid_source())?;
            input.read_exact(&mut buffer[..length]).map_err(storage)?;
            staged.write_all(&buffer[..length]).map_err(storage)?;
            remaining -= length as u64;
        }
        if input.read(&mut [0]).map_err(storage)? != 0 {
            return Err(invalid_source());
        }
        staged.as_file().sync_all().map_err(storage)?;
        staged.rewind().map_err(storage)?;
        result.verify_capture(&verify_query_capture(staged.as_file_mut(), cancel)?)?;
        Ok(staged)
    }

    pub(super) fn open_query_capture(
        &self,
        case: &CaseId,
        hash: &EvidenceHash,
        bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<File, AppError> {
        let root = self.owned_case_path(case);
        check_directory(&root)?;
        check_directory(&root.join("queries"))?;
        open_single_link(
            &root,
            &format!("queries/{}.sqc", hash.as_str()),
            bytes,
            cancel,
        )
    }

    pub(super) fn clean_orphan_query_captures(
        &self,
        case: &CaseId,
        retained: &BTreeSet<EvidenceHash>,
    ) -> Result<usize, AppError> {
        let root = self.owned_case_path(case);
        let directory = root.join("queries");
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(storage(error)),
            Ok(_) => {}
        }
        check_directory(&root)?;
        check_directory(&directory)?;
        let mut count = 0;
        for entry in fs::read_dir(&directory).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let name = entry.file_name();
            let Some(hash) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".sqc"))
                .and_then(|digest| EvidenceHash::parse(digest).ok())
            else {
                continue;
            };
            if retained.contains(&hash) || !entry.file_type().map_err(storage)?.is_file() {
                continue;
            }
            let file =
                irmind_fs::open_regular_no_follow(&directory, Path::new(&name)).map_err(storage)?;
            if !irmind_fs::regular_file_has_single_link(&file).map_err(storage)? {
                continue;
            }
            drop(file);
            fs::remove_file(entry.path()).map_err(storage)?;
            count += 1;
        }
        if count > 0 {
            irmind_fs::sync_directory(&directory).map_err(storage)?;
        }
        Ok(count)
    }
}

fn open_single_link(
    root: &Path,
    relative: &str,
    bytes: u64,
    cancel: &CancellationToken,
) -> Result<File, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if !(1..=QUERY_MAX_BYTES).contains(&bytes) {
        return Err(SourceQueryError::Limit.into());
    }
    let file = irmind_fs::open_regular_no_follow(root, Path::new(relative)).map_err(storage)?;
    if !irmind_fs::regular_file_has_single_link(&file).map_err(storage)?
        || file.metadata().map_err(storage)?.len() != bytes
    {
        return Err(invalid_source());
    }
    Ok(file)
}

fn check_directory(path: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(storage)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_source());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid_source());
        }
    }
    Ok(())
}

struct PreparedCapture {
    inner: Box<dyn PreparedMappedIngest>,
    metadata: PreparedMappedGroup,
    staged: Option<tempfile::NamedTempFile>,
    target: PathBuf,
    hash: EvidenceHash,
    bytes: u64,
    published: bool,
}

impl PreparedMappedIngest for PreparedCapture {
    fn metadata(&self) -> &PreparedMappedGroup {
        &self.metadata
    }

    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let staged = self.staged.take().ok_or_else(invalid_source)?;
        let directory = self.target.parent().ok_or_else(invalid_source)?;
        let root = directory.parent().ok_or_else(invalid_source)?;
        check_directory(root)?;
        fs::create_dir_all(directory).map_err(storage)?;
        check_directory(directory)?;
        irmind_fs::private_dir(directory).map_err(storage)?;
        self.inner.publish(cancel)?;
        let mut file = staged.persist_noclobber(&self.target).map_err(storage)?;
        self.published = true;
        if !irmind_fs::regular_file_has_single_link(&file).map_err(storage)? {
            return Err(invalid_source());
        }
        file.rewind().map_err(storage)?;
        let summary = verify_query_capture((&mut file).take(self.bytes + 1), cancel)?;
        if summary.identity() != (&self.hash, self.bytes) {
            return Err(AppError::EvidenceMismatch(self.hash.as_str().into()));
        }
        drop(file);
        irmind_fs::sync_directory(directory).map_err(storage)?;
        irmind_fs::sync_directory(root).map_err(storage)?;
        Ok(())
    }

    fn retain_committed(&mut self) {
        self.inner.retain_committed();
        self.published = false;
    }
}

impl Drop for PreparedCapture {
    fn drop(&mut self) {
        if self.published {
            let _ = fs::remove_file(&self.target);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
