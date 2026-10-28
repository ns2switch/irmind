use super::{
    AppError, AuditLog, CancellationToken, CaseId, CaseSeal, EvidenceStore, LocalStore,
    OpenOptions, Path, Repository, fs, params, private_file, storage, storage_reason,
};
use irmind_app::{ExportVerification, LargeCaseExporter};
use irmind_domain::{AuditEventKind, SourceManifestV1};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};

pub(super) const MAGIC_V4: &[u8] = b"IRMIND-EXPORT-V4\0";
pub(super) const MAX_FRAME_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeaderV4 {
    pub version: u32,
    pub case_id: String,
    pub title: String,
    pub severity: String,
    pub scope: String,
    pub seal: CaseSeal,
}

impl LargeCaseExporter for LocalStore {
    fn export_case_v4(
        &self,
        id: &CaseId,
        path: &Path,
        source_root: Option<&Path>,
        include_originals: bool,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.export_v4(id, path, source_root, include_originals, cancel)
    }
}

impl LocalStore {
    pub(super) fn export_v4(
        &self,
        id: &CaseId,
        path: &Path,
        source_root: Option<&Path>,
        include_originals: bool,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let case = self.get_case(id)?;
        if !case.sealed {
            return Err(AppError::Sealed);
        }
        let seal = self.case_seal(id)?.ok_or(AppError::InvalidChain(0))?;
        let header = HeaderV4 {
            version: 4,
            case_id: id.as_str().into(),
            title: case.title,
            severity: case.severity.as_str().into(),
            scope: case.scope,
            seal,
        };
        let entry_count = self.last_entry(id)?.ok_or(AppError::InvalidChain(0))?.seq;
        let evidence = self.evidence_hashes(id)?;
        let source_count = self
            .conn()?
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE case_id=?1 AND kind=?2",
                params![id.as_str(), AuditEventKind::SourceManifestV1.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .map_err(storage)?;
        let mut created = false;
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut out = options.open(path).map_err(storage)?;
            created = true;
            private_file(path).map_err(storage)?;
            out.write_all(MAGIC_V4).map_err(storage)?;
            write_frame(&mut out, &serde_json::to_vec(&header).map_err(storage)?)?;
            out.write_all(&entry_count.to_be_bytes()).map_err(storage)?;
            let written = self.for_each_audit_entry(id, |entry| {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                write_frame(&mut out, &serde_json::to_vec(&entry).map_err(storage)?)
            })?;
            if written as u64 != entry_count {
                return Err(AppError::InvalidChain(entry_count));
            }
            out.write_all(&(evidence.len() as u64).to_be_bytes())
                .map_err(storage)?;
            for hash in &evidence {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let content = self.get_evidence(id, hash)?;
                out.write_all(hash.as_bytes()).map_err(storage)?;
                out.write_all(&(content.len() as u64).to_be_bytes())
                    .map_err(storage)?;
                out.write_all(&content).map_err(storage)?;
            }
            out.write_all(&if include_originals { source_count } else { 0 }.to_be_bytes())
                .map_err(storage)?;
            if include_originals {
                self.write_source_bytes(id, source_root, &mut out, cancel)?;
            }
            let operations = self.operations(id)?;
            out.write_all(&(operations.len() as u64).to_be_bytes())
                .map_err(storage)?;
            for operation in operations {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                write_frame(&mut out, &serde_json::to_vec(&operation).map_err(storage)?)?;
            }
            out.sync_all().map_err(storage)?;
            Ok(header.seal.analyst_key_fingerprint.clone())
        })();
        if result.is_err() && created {
            let _ = fs::remove_file(path);
        }
        result
    }

    fn write_source_bytes(
        &self,
        id: &CaseId,
        source_root: Option<&Path>,
        out: &mut File,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.for_each_audit_entry(id, |entry| {
            if entry.kind != AuditEventKind::SourceManifestV1 {
                return Ok(());
            }
            let manifest = SourceManifestV1::decode(&entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            let mut input = if let Some(root) = source_root {
                irmind_fs::open_regular_no_follow(root, Path::new(&manifest.source))
                    .map_err(storage)?
            } else if manifest.copied {
                let case_dir = self.parquet.case_dir(id)?;
                let relative = format!("originals/{}", manifest.sha256.as_str());
                irmind_fs::open_regular_no_follow(&case_dir, Path::new(&relative))
                    .map_err(storage)?
            } else {
                return Err(storage_reason(
                    "original source is unavailable; select its root",
                ));
            };
            out.write_all(manifest.sha256.as_str().as_bytes())
                .map_err(storage)?;
            out.write_all(&manifest.size.to_be_bytes())
                .map_err(storage)?;
            copy_verified(&mut input, out, &manifest, cancel)
        })?;
        Ok(())
    }
}

fn copy_verified(
    input: &mut File,
    output: &mut File,
    manifest: &SourceManifestV1,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut read = 0u64;
    let mut chunk = vec![0u8; 1024 * 1024];
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let count = input.read(&mut chunk).map_err(storage)?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(count as u64)
            .ok_or_else(|| storage_reason("source size overflow"))?;
        if read > manifest.size {
            return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
        }
        hasher.update(&chunk[..count]);
        output.write_all(&chunk[..count]).map_err(storage)?;
    }
    if read != manifest.size || irmind_app::hex(&hasher.finalize()) != manifest.sha256.as_str() {
        return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
    }
    Ok(())
}

pub(super) fn write_frame(out: &mut File, bytes: &[u8]) -> Result<(), AppError> {
    if bytes.len() as u64 > MAX_FRAME_BYTES {
        return Err(storage_reason("export metadata frame exceeds limit"));
    }
    out.write_all(&(bytes.len() as u64).to_be_bytes())
        .map_err(storage)?;
    out.write_all(bytes).map_err(storage)
}

pub(super) fn v4_result(
    fingerprint: String,
    entries: usize,
    source_manifests: usize,
    source_bytes_verified: usize,
) -> ExportVerification {
    ExportVerification {
        analyst_key_fingerprint: fingerprint,
        entries,
        format_version: 4,
        source_manifests,
        source_bytes_verified,
        source_bytes_unavailable: source_manifests.saturating_sub(source_bytes_verified),
    }
}
