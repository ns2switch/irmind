use super::{
    AppError, AuditLog, CancellationToken, CaseId, CaseSeal, EvidenceStore, LocalStore,
    OpenOptions, Path, Repository, fs, params, private_file, storage, storage_reason,
};
use irmind_app::{
    ExportVerification, LargeCaseExporter,
    source_queries::{SourceQueryJournal, write_stored_query_capture_section},
};
use irmind_domain::{AuditEventKind, SourceManifestV1};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};

pub(super) const EXPORT_VERSION: u32 = 10;
pub(super) const MAGIC_V10: &[u8] = b"IRMIND-EXPORT-V10\0";
pub(super) const MAX_FRAME_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeaderV10 {
    pub version: u32,
    pub case_id: String,
    pub title: String,
    pub severity: String,
    pub scope: String,
    pub seal: CaseSeal,
}

struct ExportRequest<'a> {
    id: &'a CaseId,
    path: &'a Path,
    source_root: Option<&'a Path>,
    include_originals: bool,
    cancel: &'a CancellationToken,
    header: HeaderV10,
    entry_count: u64,
    evidence: Vec<String>,
    source_count: u64,
    queries: &'a SourceQueryJournal<'a>,
}

impl LargeCaseExporter for LocalStore {
    fn export_case(
        &self,
        id: &CaseId,
        path: &Path,
        source_root: Option<&Path>,
        include_originals: bool,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.export_current(id, path, source_root, include_originals, cancel)
    }
}
impl LocalStore {
    pub(super) fn export_current(
        &self,
        id: &CaseId,
        path: &Path,
        source_root: Option<&Path>,
        include_originals: bool,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let case = self.get_case(id)?;
        let entries = self.entries(id)?;
        irmind_app::verify_case_metadata(&case.title, case.severity, &case.scope, &entries)?;
        irmind_app::artifact_catalog(&entries)?;
        if !case.sealed {
            return Err(AppError::Sealed);
        }
        let seal = self.case_seal(id)?.ok_or(AppError::InvalidChain(0))?;
        let header = HeaderV10 {
            version: EXPORT_VERSION,
            case_id: id.as_str().into(),
            title: case.title,
            severity: case.severity.as_str().into(),
            scope: case.scope,
            seal,
        };
        let entry_count = self.last_entry(id)?.ok_or(AppError::InvalidChain(0))?.seq;
        let evidence = self.evidence_hashes(id)?;
        let query_operations = if entries
            .iter()
            .any(|entry| entry.kind.is_source_query_lifecycle())
        {
            self.signed_parquet_artifacts(id)?;
            self.global_operations()?
        } else {
            Vec::new()
        };
        let queries = super::local::replay_source_queries(&entries, &query_operations, cancel)?;
        let source_count = self
            .source_manifest_count(id)?
            .checked_sub(queries.captures().len() as u64)
            .ok_or(AppError::InvalidChain(entry_count))?;
        let mut created = false;
        let result = self.write_current_body(
            &ExportRequest {
                id,
                path,
                source_root,
                include_originals,
                cancel,
                header,
                entry_count,
                evidence,
                source_count,
                queries: &queries,
            },
            &mut created,
        );
        if result.is_err() && created {
            let _ = fs::remove_file(path);
        }
        result
    }

    fn source_manifest_count(&self, id: &CaseId) -> Result<u64, AppError> {
        self.conn()?
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE case_id=?1 AND kind=?2",
                params![id.as_str(), AuditEventKind::SourceManifestV2.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .map_err(storage)
    }

    fn write_current_body(
        &self,
        request: &ExportRequest<'_>,
        created: &mut bool,
    ) -> Result<String, AppError> {
        let ExportRequest {
            id,
            path,
            source_root,
            include_originals,
            cancel,
            header,
            entry_count,
            evidence,
            source_count,
            queries,
        } = request;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut out = options.open(path).map_err(storage)?;
        *created = true;
        private_file(path).map_err(storage)?;
        write_header(&mut out, header)?;
        out.write_all(&entry_count.to_be_bytes()).map_err(storage)?;
        let written = self.for_each_audit_entry(id, |entry| {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            write_frame(&mut out, &serde_json::to_vec(&entry).map_err(storage)?)
        })?;
        if written as u64 != *entry_count {
            return Err(AppError::InvalidChain(*entry_count));
        }
        out.write_all(&(evidence.len() as u64).to_be_bytes())
            .map_err(storage)?;
        for hash in evidence {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let content = self.get_evidence(id, hash)?;
            out.write_all(hash.as_bytes()).map_err(storage)?;
            out.write_all(&(content.len() as u64).to_be_bytes())
                .map_err(storage)?;
            out.write_all(&content).map_err(storage)?;
        }
        out.write_all(&if *include_originals { *source_count } else { 0 }.to_be_bytes())
            .map_err(storage)?;
        if *include_originals {
            self.write_source_bytes(id, *source_root, queries, &mut out, cancel)?;
        }
        let operations = self.operations(id)?;
        out.write_all(&((operations.len() + queries.adoptions().len()) as u64).to_be_bytes())
            .map_err(storage)?;
        for operation in operations.iter().chain(queries.adoptions()) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            write_frame(&mut out, &serde_json::to_vec(operation).map_err(storage)?)?;
        }
        super::mapping_proofs::write(self, id, &header.seal.public_key, &mut out, cancel)?;
        self.write_artifact_frames(id, &mut out, cancel)?;
        let (catalog, mut skills) =
            super::skill_proofs::write(self, id, &header.seal.public_key, &mut out, cancel)?;
        // The catalog and subagent counts are mandatory, including when unused.
        super::catalog_proofs::write(&mut out, &catalog, cancel)?;
        super::subagent_branches::write(
            self,
            id,
            &header.seal.public_key,
            &mut skills,
            &mut out,
            cancel,
        )?;
        write_stored_query_capture_section(&mut out, queries.captures(), self, id, cancel)?;
        super::extensions::write(self, id, &mut out, cancel)?;
        out.sync_all().map_err(storage)?;
        Ok(header.seal.analyst_key_fingerprint.clone())
    }

    fn write_source_bytes(
        &self,
        id: &CaseId,
        source_root: Option<&Path>,
        queries: &SourceQueryJournal<'_>,
        out: &mut File,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.for_each_audit_entry(id, |entry| {
            let Some(manifest) = SourceManifestV1::decode_signed(entry.kind, &entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?
            else {
                return Ok(());
            };
            if queries.contains_capture(&manifest.sha256) {
                return Ok(());
            }
            let mut input = if manifest.copied {
                let case_dir = self.parquet.case_dir(id)?;
                let relative = format!("originals/{}", manifest.sha256.as_str());
                irmind_fs::open_regular_no_follow(&case_dir, Path::new(&relative))
                    .map_err(storage)?
            } else if let Some(root) = source_root {
                irmind_fs::open_regular_no_follow(root, Path::new(&manifest.source))
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

pub(super) fn copy_verified(
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

pub(super) fn write_header(out: &mut File, header: &HeaderV10) -> Result<(), AppError> {
    out.write_all(MAGIC_V10).map_err(storage)?;
    write_frame(out, &serde_json::to_vec(header).map_err(storage)?)
}

pub(super) fn write_frame(out: &mut File, bytes: &[u8]) -> Result<(), AppError> {
    if bytes.len() as u64 > MAX_FRAME_BYTES {
        return Err(storage_reason("export metadata frame exceeds limit"));
    }
    out.write_all(&(bytes.len() as u64).to_be_bytes())
        .map_err(storage)?;
    out.write_all(bytes).map_err(storage)
}

pub(super) fn v10_result(
    fingerprint: String,
    entries: usize,
    source_manifests: usize,
    source_bytes_verified: usize,
) -> ExportVerification {
    ExportVerification {
        analyst_key_fingerprint: fingerprint,
        entries,
        format_version: EXPORT_VERSION,
        source_manifests,
        source_bytes_verified,
        source_bytes_unavailable: source_manifests.saturating_sub(source_bytes_verified),
        source_query_limits: Vec::new(),
    }
}
