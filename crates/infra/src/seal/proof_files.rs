//! Stage immutable case proof files before appending their signed receipt.
use crate::{AppError, CancellationToken, CaseId, LocalStore, Repository};
use irmind_app::v10_proofs::{V10ProofDescriptor, V10ProofFamily, v10_proof_commitment};
use std::{
    fs::{self, File},
    io::{Read as _, Seek, Write as _},
    path::{Path, PathBuf},
};

const MAX_PROOF_BYTES: u64 = 128 * 1024 * 1024;
const DISK_MARGIN: u64 = 16 * 1024 * 1024;

pub struct V10PreparedObjects {
    staged: Vec<(V10ProofDescriptor, tempfile::NamedTempFile)>,
    published: Vec<PathBuf>,
    root: PathBuf,
    retained: bool,
}

impl LocalStore {
    /// The engine holds the case write lock from preparation through append.
    pub fn prepare_v10_case_objects(
        &self,
        case: &CaseId,
        family: V10ProofFamily,
        items: &[(V10ProofDescriptor, &[u8])],
        cancel: &CancellationToken,
    ) -> Result<V10PreparedObjects, AppError> {
        check_cancel(cancel)?;
        if self.get_case(case)?.sealed {
            return Err(AppError::Sealed);
        }
        let descriptors = items
            .iter()
            .map(|(descriptor, _)| *descriptor)
            .collect::<Vec<_>>();
        v10_proof_commitment(family, &descriptors).map_err(|_| invalid())?;
        let case_dir = self.parquet.owned_case_path(case);
        ensure_directory(case_dir.parent().ok_or_else(invalid)?, false)?;
        ensure_directory(&case_dir, true)?;
        let root = case_dir.join(namespace(family));
        ensure_directory(&root, true)?;

        let mut missing = Vec::new();
        for (descriptor, body) in items {
            check_cancel(cancel)?;
            if V10ProofDescriptor::from_body(family, descriptor.kind(), body)
                .map_err(|_| invalid())?
                != *descriptor
            {
                return Err(invalid());
            }
            match fs::symlink_metadata(root.join(filename(*descriptor))) {
                Ok(_) => {
                    open_object(&root, *descriptor, cancel)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push((*descriptor, *body));
                }
                Err(_) => return Err(invalid()),
            }
        }
        let added = missing
            .iter()
            .map(|(descriptor, _)| descriptor.size())
            .sum::<u64>();
        preflight(&root, added, cancel)?;
        let mut staged = Vec::with_capacity(missing.len());
        for (descriptor, body) in missing {
            let mut file = tempfile::Builder::new()
                .prefix(".prepared-")
                .tempfile_in(&root)
                .map_err(|_| invalid())?;
            irmind_fs::private_file(file.path()).map_err(|_| invalid())?;
            for block in body.chunks(64 * 1024) {
                check_cancel(cancel)?;
                file.write_all(block).map_err(|_| invalid())?;
            }
            file.as_file().sync_all().map_err(|_| invalid())?;
            staged.push((descriptor, file));
        }
        Ok(V10PreparedObjects {
            staged,
            published: Vec::new(),
            root,
            retained: false,
        })
    }

    pub(super) fn open_addressed_report_proof(
        &self,
        case: &CaseId,
        kind: u8,
        hash: [u8; 32],
        cancel: &CancellationToken,
    ) -> Result<(V10ProofDescriptor, File), AppError> {
        self.open_addressed_v10_proof(case, V10ProofFamily::Report, kind, hash, cancel)
    }

    pub(super) fn open_addressed_v10_proof(
        &self,
        case: &CaseId,
        family: V10ProofFamily,
        kind: u8,
        hash: [u8; 32],
        cancel: &CancellationToken,
    ) -> Result<(V10ProofDescriptor, File), AppError> {
        check_cancel(cancel)?;
        let case_dir = self.parquet.owned_case_path(case);
        ensure_directory(case_dir.parent().ok_or_else(invalid)?, false)?;
        ensure_directory(&case_dir, false)?;
        let root = case_dir.join(namespace(family));
        ensure_directory(&root, false)?;
        let name = format!("{}-{}.proof", kind, irmind_app::hex(&hash));
        let file =
            irmind_fs::open_regular_no_follow(&root, Path::new(&name)).map_err(|_| invalid())?;
        let bytes = file.metadata().map_err(|_| invalid())?.len();
        let descriptor =
            V10ProofDescriptor::new(family, kind, hash, bytes).map_err(|_| invalid())?;
        Ok((descriptor, verify_open_object(file, descriptor, cancel)?))
    }

    pub(crate) fn read_addressed_report_proof(
        &self,
        case: &CaseId,
        kind: u8,
        hash: [u8; 32],
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        self.read_addressed_v10_proof(case, V10ProofFamily::Report, kind, hash, cancel)
    }

    pub(crate) fn read_addressed_v10_proof(
        &self,
        case: &CaseId,
        family: V10ProofFamily,
        kind: u8,
        hash: [u8; 32],
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let (descriptor, mut file) =
            self.open_addressed_v10_proof(case, family, kind, hash, cancel)?;
        let len = usize::try_from(descriptor.size()).map_err(|_| invalid())?;
        let mut data = vec![0; len];
        for block in data.chunks_mut(64 * 1024) {
            check_cancel(cancel)?;
            file.read_exact(block).map_err(|_| invalid())?;
        }
        check_cancel(cancel)?;
        if irmind_app::sha256(&data) != hash {
            return Err(invalid());
        }
        Ok(data)
    }

    pub fn open_v10_case_object(
        &self,
        case: &CaseId,
        family: V10ProofFamily,
        descriptor: V10ProofDescriptor,
        cancel: &CancellationToken,
    ) -> Result<File, AppError> {
        V10ProofDescriptor::decode(family, &descriptor.encode()).map_err(|_| invalid())?;
        let case_dir = self.parquet.owned_case_path(case);
        ensure_directory(case_dir.parent().ok_or_else(invalid)?, false)?;
        ensure_directory(&case_dir, false)?;
        let root = case_dir.join(namespace(family));
        ensure_directory(&root, false)?;
        open_object(&root, descriptor, cancel)
    }
}

impl V10PreparedObjects {
    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        for (descriptor, staging) in self.staged.drain(..) {
            check_cancel(cancel)?;
            let target = self.root.join(filename(descriptor));
            staging.persist_noclobber(&target).map_err(|_| invalid())?;
            self.published.push(target);
            open_object(&self.root, descriptor, cancel)?;
        }
        irmind_fs::sync_directory(&self.root).map_err(|_| invalid())?;
        irmind_fs::sync_directory(self.root.parent().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        Ok(())
    }

    /// Append the signed receipt after publishing and syncing the immutable
    /// objects. A failed append rolls back only objects created by this stage.
    pub fn append_with<T>(
        mut self,
        cancel: &CancellationToken,
        append: impl FnOnce() -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        self.publish(cancel)?;
        check_cancel(cancel)?;
        let result = append()?;
        self.retained = true;
        Ok(result)
    }
}

impl Drop for V10PreparedObjects {
    fn drop(&mut self) {
        if !self.retained {
            for path in &self.published {
                let _ = fs::remove_file(path);
            }
            let _ = irmind_fs::sync_directory(&self.root);
        }
    }
}

fn preflight(root: &Path, staged: u64, cancel: &CancellationToken) -> Result<(), AppError> {
    let mut remaining = MAX_PROOF_BYTES.checked_sub(staged).ok_or_else(invalid)?;
    for (index, entry) in fs::read_dir(root).map_err(|_| invalid())?.enumerate() {
        if index == 1_000_000 {
            return Err(invalid());
        }
        check_cancel(cancel)?;
        let entry = entry.map_err(|_| invalid())?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| invalid())?;
        if !metadata.is_file() || is_link(&metadata) {
            return Err(invalid());
        }
        remaining = remaining.checked_sub(metadata.len()).ok_or_else(invalid)?;
    }
    let available = fs4::available_space(root).map_err(|_| invalid())?;
    if available < staged + DISK_MARGIN {
        return Err(AppError::Storage(
            "insufficient space to stage case proof objects".into(),
        ));
    }
    Ok(())
}

fn open_object(
    root: &Path,
    descriptor: V10ProofDescriptor,
    cancel: &CancellationToken,
) -> Result<File, AppError> {
    check_cancel(cancel)?;
    let file = irmind_fs::open_regular_no_follow(root, Path::new(&filename(descriptor)))
        .map_err(|_| invalid())?;
    verify_open_object(file, descriptor, cancel)
}

fn verify_open_object(
    mut file: File,
    descriptor: V10ProofDescriptor,
    cancel: &CancellationToken,
) -> Result<File, AppError> {
    if file.metadata().map_err(|_| invalid())?.len() != descriptor.size()
        || !irmind_fs::regular_file_has_single_link(&file).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    super::frames::verify_raw_with_cancel(
        &mut file,
        descriptor.size(),
        &irmind_app::hex(&descriptor.hash()),
        Some(cancel),
    )?;
    file.rewind().map_err(|_| invalid())?;
    Ok(file)
}

fn ensure_directory(path: &Path, create: bool) -> Result<(), AppError> {
    if create {
        match fs::create_dir(path) {
            Ok(()) => irmind_fs::private_dir(path).map_err(|_| invalid())?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(invalid()),
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !metadata.is_dir() || is_link(&metadata) {
        return Err(invalid());
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn namespace(family: V10ProofFamily) -> &'static str {
    match family {
        V10ProofFamily::Sigma => "sigma-proofs",
        V10ProofFamily::Report => "report-proofs",
    }
}

fn filename(descriptor: V10ProofDescriptor) -> String {
    format!(
        "{}-{}.proof",
        descriptor.kind(),
        irmind_app::hex(&descriptor.hash())
    )
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    Ok(())
}

fn invalid() -> AppError {
    AppError::Storage("case proof file is unavailable or invalid".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn staged(root: &Path, descriptor: V10ProofDescriptor, body: &[u8]) -> V10PreparedObjects {
        let mut object = tempfile::NamedTempFile::new_in(root).unwrap();
        object.write_all(body).unwrap();
        object.as_file().sync_all().unwrap();
        V10PreparedObjects {
            staged: vec![(descriptor, object)],
            published: Vec::new(),
            root: root.to_path_buf(),
            retained: false,
        }
    }

    #[test]
    fn case_proof_rollback_preserves_existing_objects_and_commits_exact_bytes() {
        let root = tempfile::tempdir().unwrap();
        let body = b"Synthetic PDF literal";
        let object = V10ProofDescriptor::from_body(V10ProofFamily::Report, 3, body).unwrap();
        let path = root.path().join(filename(object));
        let cancel = CancellationToken::new();
        let failed = staged(root.path(), object, body).append_with(&cancel, || {
            assert_eq!(fs::read(&path).unwrap(), body);
            Err::<(), _>(AppError::Sealed)
        });
        assert!(matches!(failed, Err(AppError::Sealed)));
        assert!(!path.exists());

        staged(root.path(), object, body)
            .append_with(&cancel, || Ok(()))
            .unwrap();
        assert!(open_object(root.path(), object, &cancel).is_ok());
        let collision = staged(root.path(), object, b"replacement").append_with(&cancel, || Ok(()));
        assert!(collision.is_err());
        assert_eq!(fs::read(&path).unwrap(), body);
    }
}
