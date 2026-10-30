use crate::{
    AppError, AuditLog, CaseId, EvidenceStore, LocalStore, OpenOptions, Path, PathBuf, Read,
    Repository, Write, fs, hex, params, private_file, sha256, storage, storage_reason,
};
use irmind_domain::{AuditEventKind, SourceManifestV1};

pub(crate) fn read_evidence_file(path: &Path) -> Result<Vec<u8>, AppError> {
    let file = fs::File::open(path).map_err(storage)?;
    if file.metadata().map_err(storage)?.len() > 50_000_000 {
        return Err(storage_reason("evidence file exceeds 50 MB"));
    }
    let mut bytes = Vec::new();
    file.take(50_000_001)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() > 50_000_000 {
        return Err(storage_reason("evidence file exceeds 50 MB"));
    }
    Ok(bytes)
}

impl LocalStore {
    fn evidence_path(&self, hash: &str) -> Result<PathBuf, AppError> {
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(storage_reason("invalid evidence hash"));
        }
        Ok(self.evidence_dir.join(hash.to_ascii_lowercase()))
    }

    fn signed_source(&self, id: &CaseId, hash: &str) -> Result<Option<SourceManifestV1>, AppError> {
        self.signed_parquet_artifacts(id)?;
        for entry in self.entries(id)? {
            if entry.kind == AuditEventKind::SourceManifestV1 {
                let source = SourceManifestV1::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if source.sha256.as_str() == hash {
                    return Ok(Some(source));
                }
            }
        }
        Ok(None)
    }

    fn read_copied_source(
        &self,
        id: &CaseId,
        source: &SourceManifestV1,
    ) -> Result<Vec<u8>, AppError> {
        if !source.copied {
            return Err(storage_reason(
                "original source was not copied; open it from its recorded location",
            ));
        }
        let case_dir = self.parquet.case_dir(id)?;
        let relative = PathBuf::from(format!("originals/{}", source.sha256.as_str()));
        let file = irmind_fs::open_regular_no_follow(&case_dir, &relative).map_err(storage)?;
        if file.metadata().map_err(storage)?.len() > 50_000_000 {
            return Err(storage_reason(
                "copied source exceeds the 50 MB evidence-view limit",
            ));
        }
        let mut bytes = Vec::new();
        file.take(50_000_001)
            .read_to_end(&mut bytes)
            .map_err(storage)?;
        if bytes.len() as u64 != source.size || hex(&sha256(&bytes)) != source.sha256.as_str() {
            return Err(AppError::EvidenceMismatch(source.sha256.as_str().into()));
        }
        Ok(bytes)
    }
}
impl EvidenceStore for LocalStore {
    fn put_evidence(&self, id: &CaseId, hash: &str, bytes: &[u8]) -> Result<(), AppError> {
        if self.get_case(id)?.sealed || self.seal_dir.join(format!("{}.json", id.as_str())).exists()
        {
            return Err(AppError::Sealed);
        }
        if hex(&sha256(bytes)) != hash {
            return Err(storage_reason("evidence hash does not match content"));
        }
        let path = self.evidence_path(hash)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                private_file(&path).map_err(storage)?;
                file.write_all(bytes).map_err(storage)?;
                file.sync_all().map_err(storage)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_evidence_file(&path)? != bytes {
                    return Err(storage_reason("existing evidence differs"));
                }
            }
            Err(e) => return Err(storage(e)),
        }
        self.conn()?
            .execute(
                "INSERT OR IGNORE INTO evidence (case_id,hash) VALUES (?1,?2)",
                params![id.as_str(), hash],
            )
            .map_err(storage)?;
        Ok(())
    }

    fn get_evidence(&self, id: &CaseId, hash: &str) -> Result<Vec<u8>, AppError> {
        let path = self.evidence_path(hash)?;
        let exists: i64 = self
            .conn()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM evidence WHERE case_id=?1 AND hash=?2)",
                params![id.as_str(), hash],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if exists == 0 {
            let source = self
                .signed_source(id, &hash.to_ascii_lowercase())?
                .ok_or_else(|| storage_reason("evidence not in case"))?;
            return self.read_copied_source(id, &source);
        }
        let bytes = read_evidence_file(&path)?;
        if hex(&sha256(&bytes)) != hash.to_ascii_lowercase() {
            return Err(AppError::EvidenceMismatch(hash.to_owned()));
        }
        Ok(bytes)
    }

    fn evidence_hashes(&self, id: &CaseId) -> Result<Vec<String>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT hash FROM evidence WHERE case_id=?1 ORDER BY hash")
            .map_err(storage)?;
        stmt.query_map([id.as_str()], |row| row.get(0))
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
    }

    fn search_evidence(
        &self,
        id: &CaseId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<String>, AppError> {
        let mut result = Vec::new();
        for hash in self.evidence_hashes(id)? {
            let bytes = self.get_evidence(id, &hash)?;
            let text = String::from_utf8_lossy(&bytes);
            if let Some(offset) = text.to_ascii_lowercase().find(&query.to_ascii_lowercase()) {
                let start = text.floor_char_boundary(offset.saturating_sub(80));
                let end = text.ceil_char_boundary((offset + query.len() + 80).min(text.len()));
                result.push(format!("{hash}: {}", &text[start..end]));
                if result.len() >= limit {
                    break;
                }
            }
        }
        Ok(result)
    }
}
