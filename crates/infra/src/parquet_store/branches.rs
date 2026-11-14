use super::{AppError, CaseId, ParquetStore, fs, storage};
use irmind_app::{
    CancellationToken,
    subagents::{
        BoundedBranchBytes, BranchChunkRef, CheckedBranchChunk, PublishedBranchChunk,
        StagedBranchChunk, SubagentBranchStore,
    },
};
use std::{
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::Path,
};

fn active(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(AppError::Cancelled)
    } else {
        Ok(())
    }
}
fn invalid() -> AppError {
    AppError::Storage("subagent branch chunk is missing, changed or exceeds its bound".into())
}

impl SubagentBranchStore for ParquetStore {
    fn stage(
        &self,
        case: &CaseId,
        chunk: &CheckedBranchChunk,
        cancel: &CancellationToken,
    ) -> Result<StagedBranchChunk, AppError> {
        active(cancel)?;
        let reference =
            BranchChunkRef::new(chunk.hash(), chunk.bytes().len() as u64).map_err(|_| invalid())?;
        let mut file = self.create_private_object_spool(case, reference.len())?;
        file.write_all(chunk.bytes()).map_err(storage)?;
        file.as_file().sync_all().map_err(storage)?;
        active(cancel)?;
        Ok(StagedBranchChunk::new(
            case.clone(),
            reference,
            file,
            cancel.clone(),
        ))
    }

    fn publish(&self, staged: StagedBranchChunk) -> Result<PublishedBranchChunk, AppError> {
        let (case, reference, mut file, cancel) = staged.into_parts();
        active(&cancel)?;
        let case_dir = self.case_dir(&case)?;
        if file.path().parent() != Some(self.spool_dir(&case)?.as_path()) {
            return Err(invalid());
        }
        file.seek(SeekFrom::Start(0)).map_err(storage)?;
        let bytes = read_bounded(file.as_file(), &reference, &cancel)?;
        BoundedBranchBytes::checked(bytes, &reference).map_err(|_| invalid())?;
        let directory = case_dir.join("branches");
        fs::create_dir_all(&directory).map_err(storage)?;
        irmind_fs::private_dir(&directory).map_err(storage)?;
        let destination = case_dir.join(reference.relative_path());
        active(&cancel)?;
        match file.persist_noclobber(&destination) {
            Ok(published) => published.sync_all().map_err(storage)?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.read(&case, &reference, &cancel)?;
                drop(error.file);
            }
            Err(error) => return Err(storage(error.error)),
        }
        irmind_fs::sync_directory(&directory).map_err(storage)?;
        irmind_fs::sync_directory(&case_dir).map_err(storage)?;
        active(&cancel)?;
        Ok(PublishedBranchChunk { case, reference })
    }

    fn read(
        &self,
        case: &CaseId,
        reference: &BranchChunkRef,
        cancel: &CancellationToken,
    ) -> Result<BoundedBranchBytes, AppError> {
        active(cancel)?;
        let file = irmind_fs::open_regular_no_follow(
            &self.root.join(case.as_str()),
            Path::new(&reference.relative_path()),
        )
        .map_err(|_| invalid())?;
        if !irmind_fs::regular_file_has_single_link(&file).map_err(storage)? {
            return Err(invalid());
        }
        let bytes = read_bounded(&file, reference, cancel)?;
        BoundedBranchBytes::checked(bytes, reference).map_err(|_| invalid())
    }

    fn discard(&self, staged: StagedBranchChunk) -> Result<(), AppError> {
        let (_, _, file, _) = staged.into_parts();
        file.close().map_err(storage)
    }
}

fn read_bounded(
    mut file: &fs::File,
    reference: &BranchChunkRef,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    active(cancel)?;
    if file.metadata().map_err(storage)?.len() != reference.len() {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(reference.len()).map_err(|_| invalid())?);
    (&mut file)
        .take(reference.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    active(cancel)?;
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
