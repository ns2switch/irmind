use fs4::fs_std::FileExt as _;
use irmind_app::{
    AppError, CancellationToken,
    catalog::{CatalogIndexBytes, CatalogProofId, CatalogProofStore, VerifiedCatalogIndex},
};
use irmind_domain::CaseId;
use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

const MAX_PROOFS: usize = 256;
const MAX_FILE: u64 = 1024 * 1024 + 8 + 64;
const MARGIN: u64 = 64 * 1024 * 1024;

/// Case and global proofs have separate immutable namespaces and quotas.
pub struct FileCatalogProofStore {
    home: PathBuf,
}

impl FileCatalogProofStore {
    pub fn new(home: &Path) -> Self {
        Self { home: home.into() }
    }

    fn root(&self, case: Option<&CaseId>, create: bool) -> Result<PathBuf, AppError> {
        private_directory(&self.home, false)?;
        let components = case.map_or_else(
            || vec!["catalog-proofs"],
            |case| vec!["parquet", case.as_str(), "catalog-proofs"],
        );
        let mut dir = self.home.clone();
        for part in components {
            dir.push(part);
            private_directory(&dir, create)?;
        }
        Ok(dir)
    }

    fn read_at(dir: &Path, id: &CatalogProofId) -> Result<CatalogIndexBytes, AppError> {
        let file = irmind_fs::open_regular_no_follow(dir, Path::new(&filename(id)))
            .map_err(|_| storage())?;
        if !irmind_fs::regular_file_has_single_link(&file).map_err(|_| storage())?
            || file.metadata().map_err(|_| storage())?.len() > MAX_FILE
        {
            return Err(storage());
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| storage())?;
        let header: [u8; 8] = bytes
            .get(..8)
            .ok_or_else(storage)?
            .try_into()
            .map_err(|_| storage())?;
        let len = usize::try_from(u64::from_be_bytes(header)).map_err(|_| storage())?;
        if len == 0 || len > 1024 * 1024 || bytes.len() != 8 + len + 64 {
            return Err(storage());
        }
        let raw = CatalogIndexBytes::new(bytes[8..8 + len].to_vec(), &bytes[8 + len..])?;
        if &raw.proof_id() != id {
            return Err(storage());
        }
        Ok(raw)
    }

    fn publish_at(
        &self,
        case: Option<&CaseId>,
        proof: &VerifiedCatalogIndex,
        cancel: &CancellationToken,
    ) -> Result<CatalogProofId, AppError> {
        check(cancel)?;
        let dir = self.root(case, true)?;
        let _lock = lock(&dir, cancel)?;
        let id = proof.proof_id();
        let target = dir.join(filename(&id));
        match fs::symlink_metadata(&target) {
            Ok(_) => {
                Self::read_at(&dir, &id)?;
                check(cancel)?;
                return Ok(id);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage()),
        }
        let len = proof.raw().index().len() as u64 + 8 + 64;
        let max_bytes = if case.is_some() { 16 } else { 64 } * 1024 * 1024;
        quota(&dir, len, max_bytes, cancel)?;
        preflight(fs4::available_space(&dir).map_err(|_| storage())?, len)?;
        let mut staging = tempfile::Builder::new()
            .prefix(".proof-")
            .tempfile_in(&dir)
            .map_err(|_| storage())?;
        irmind_fs::private_file(staging.path()).map_err(|_| storage())?;
        staging
            .write_all(&(proof.raw().index().len() as u64).to_be_bytes())
            .map_err(|_| storage())?;
        for chunk in proof.raw().index().chunks(64 * 1024) {
            check(cancel)?;
            staging.write_all(chunk).map_err(|_| storage())?;
        }
        staging
            .write_all(proof.raw().signature())
            .map_err(|_| storage())?;
        staging.as_file().sync_all().map_err(|_| storage())?;
        check(cancel)?;
        let published = staging.persist_noclobber(&target).map_err(|_| storage())?;
        published.sync_all().map_err(|_| storage())?;
        irmind_fs::sync_directory(&dir).map_err(|_| storage())?;
        Self::read_at(&dir, &id)?;
        Ok(id)
    }

    fn read_scope(
        &self,
        case: Option<&CaseId>,
        id: &CatalogProofId,
        cancel: &CancellationToken,
    ) -> Result<CatalogIndexBytes, AppError> {
        check(cancel)?;
        let bytes = Self::read_at(&self.root(case, false)?, id)?;
        check(cancel)?;
        Ok(bytes)
    }
}

impl CatalogProofStore for FileCatalogProofStore {
    fn publish(
        &self,
        proof: &VerifiedCatalogIndex,
        cancel: &CancellationToken,
    ) -> Result<CatalogProofId, AppError> {
        self.publish_at(None, proof, cancel)
    }
    fn read(
        &self,
        id: &CatalogProofId,
        cancel: &CancellationToken,
    ) -> Result<CatalogIndexBytes, AppError> {
        self.read_scope(None, id, cancel)
    }
    fn publish_for_case(
        &self,
        case: &CaseId,
        proof: &VerifiedCatalogIndex,
        cancel: &CancellationToken,
    ) -> Result<CatalogProofId, AppError> {
        self.publish_at(Some(case), proof, cancel)
    }
    fn read_for_case(
        &self,
        case: &CaseId,
        id: &CatalogProofId,
        cancel: &CancellationToken,
    ) -> Result<CatalogIndexBytes, AppError> {
        self.read_scope(Some(case), id, cancel)
    }
}

fn filename(id: &CatalogProofId) -> String {
    format!("{}.proof", irmind_app::hex(id.digest().as_bytes()))
}
fn storage() -> AppError {
    AppError::Storage(
        "catalog proof is missing, altered or unavailable; explicitly import its verified index"
            .into(),
    )
}
fn check(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(AppError::Cancelled)
    } else {
        Ok(())
    }
}
fn private_directory(path: &Path, create: bool) -> Result<(), AppError> {
    if create {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(storage()),
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|_| storage())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(storage());
    }
    irmind_fs::private_dir(path).map_err(|_| storage())
}
fn preflight(available: u64, bytes: u64) -> Result<(), AppError> {
    if available < bytes.checked_add(MARGIN).ok_or_else(storage)? {
        return Err(AppError::Storage(
            "not enough free space for the catalog proof and safety margin".into(),
        ));
    }
    Ok(())
}
fn lock(dir: &Path, cancel: &CancellationToken) -> Result<fs::File, AppError> {
    // A fully private lock file is published without clobbering before opening it.
    let stage = tempfile::Builder::new()
        .prefix(".lock-")
        .tempfile_in(dir)
        .map_err(|_| storage())?;
    irmind_fs::private_file(stage.path()).map_err(|_| storage())?;
    if let Err(error) = stage.persist_noclobber(dir.join("store.lock"))
        && error.error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(storage());
    }
    let file =
        irmind_fs::open_regular_no_follow(dir, Path::new("store.lock")).map_err(|_| storage())?;
    if !irmind_fs::regular_file_has_single_link(&file).map_err(|_| storage())? {
        return Err(storage());
    }
    loop {
        check(cancel)?;
        if file.try_lock_exclusive().map_err(|_| storage())? {
            return Ok(file);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
fn quota(dir: &Path, added: u64, cap: u64, cancel: &CancellationToken) -> Result<(), AppError> {
    let mut count = 0usize;
    let mut total = added;
    for (entries, entry) in fs::read_dir(dir).map_err(|_| storage())?.enumerate() {
        check(cancel)?;
        if entries > 1024 {
            return Err(storage());
        }
        let entry = entry.map_err(|_| storage())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(storage)?;
        if name == "store.lock" || name.starts_with(".lock-") {
            continue;
        }
        if name.starts_with(".proof-") {
            // Serialized publishers cannot own a live staging file here.
            fs::remove_file(entry.path()).map_err(|_| storage())?;
            continue;
        }
        let id = name.strip_suffix(".proof").ok_or_else(storage)?;
        CatalogProofId::parse(id)?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|_| storage())?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_FILE {
            return Err(storage());
        }
        count += 1;
        total = total.checked_add(meta.len()).ok_or_else(storage)?;
        if count >= MAX_PROOFS || total > cap {
            return Err(AppError::Storage(
                "catalog proof store is full; no referenced proofs were removed".into(),
            ));
        }
    }
    if total > cap {
        return Err(storage());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
