use crate::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, Engine, LargeCaseStore,
    StreamingEventParser, sha256,
};

mod direct;
mod manifest;
mod mapped_compaction;
mod source_event;
mod verification;
use irmind_domain::{
    EvidenceHash, ParquetArtifact, ParserSelectionMode, SourceManifestV1, SourceManifestV2,
};
pub(crate) use manifest::read_manifest_index;
use manifest::select_sources;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct LargeCaseUseCases<'a, 'ports> {
    pub engine: &'a Engine<'ports>,
    pub store: &'a dyn LargeCaseStore,
    pub parser: &'a dyn StreamingEventParser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCheckMode {
    Full,
    Sample(usize),
}

#[derive(Debug)]
pub struct SourceCheckReport {
    pub total: usize,
    pub checked: usize,
    pub missing_or_changed: Vec<String>,
    pub unchecked: usize,
}

pub(crate) struct ManifestIndex {
    pub sources: Vec<SourceManifestV1>,
    pub artifacts: Vec<ParquetArtifact>,
}

#[derive(Clone, Debug)]
pub struct ParserSelection {
    pub parser_id: String,
    pub parser_version: String,
    pub confidence: u8,
    pub mode: ParserSelectionMode,
    pub timestamp_context: Option<String>,
    pub cluster_context: Option<crate::SourceClusterContext>,
    pub format_sample_sha256: [u8; 32],
}

impl LargeCaseUseCases<'_, '_> {
    /// Sign bounded, reproducible Parquet bundles after ingest. Historical
    /// single-source artifacts remain available for full reconstruction.
    pub fn compact_case(&self, id: &CaseId, cancel: &CancellationToken) -> Result<usize, AppError> {
        self.compact_case_with_threshold(id, 16, cancel)
    }

    /// Explicit maintenance only: direct files are compacted above this count
    /// per compatible partition/schema; initial ingestion never calls it.
    pub fn compact_case_with_threshold(
        &self,
        id: &CaseId,
        small_file_threshold: usize,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if !(2..=4096).contains(&small_file_threshold) {
            return Err(AppError::Policy(
                "invalid small-file maintenance threshold".into(),
            ));
        }
        self.engine.require_attended_analyst("compact Parquet")?;
        let _case_lock = self.engine.repo.lock_case(id)?;
        if self.engine.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.engine.verify_ingest_checkpoint(id, cancel)?;
        let index = crate::artifact_catalog(&self.engine.audit_log.entries(id)?)?.active;
        let known = index
            .into_iter()
            .map(|a| (a.path().to_owned(), a))
            .collect();
        let compacted = self.compact_mapped(id, &known, small_file_threshold, cancel)?;
        self.engine.verify_ingest_checkpoint(id, cancel)?;
        Ok(compacted)
    }

    pub fn ingest_local(
        &self,
        id: &CaseId,
        source_root: &Path,
        relative_path: &str,
        copy_original: bool,
        cancel: &CancellationToken,
    ) -> Result<EvidenceHash, AppError> {
        let mut ingested = self.ingest_local_batch(
            id,
            source_root,
            &[relative_path.to_owned()],
            copy_original,
            cancel,
        )?;
        ingested
            .pop()
            .map(|(_, hash)| hash)
            .ok_or_else(invalid_manifest)
    }

    /// Prepare at most four independent files at a time, then sign their
    /// manifests in sorted order. This bounds memory and makes the audit chain
    /// deterministic even when hashing and parsing finish out of order.
    pub fn ingest_local_batch(
        &self,
        id: &CaseId,
        source_root: &Path,
        relative_paths: &[String],
        copy_original: bool,
        cancel: &CancellationToken,
    ) -> Result<Vec<(String, EvidenceHash)>, AppError> {
        self.ingest_local_batch_selected(
            id,
            source_root,
            relative_paths,
            copy_original,
            &BTreeMap::new(),
            cancel,
        )
    }

    pub fn ingest_local_batch_selected(
        &self,
        id: &CaseId,
        source_root: &Path,
        relative_paths: &[String],
        copy_original: bool,
        selections: &BTreeMap<String, ParserSelection>,
        cancel: &CancellationToken,
    ) -> Result<Vec<(String, EvidenceHash)>, AppError> {
        self.engine.require_attended_analyst("ingest source")?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let _case_lock = self.engine.repo.lock_case(id)?;
        if self.engine.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.engine.verify_ingest_checkpoint(id, cancel)?;
        let mut ordered = relative_paths.to_vec();
        ordered.sort();
        if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AppError::Policy("duplicate source path in batch".into()));
        }
        let index = read_manifest_index(&self.engine.audit_log.entries(id)?)?;
        let mut known_artifacts = index
            .artifacts
            .into_iter()
            .map(|artifact| (artifact.path().to_owned(), artifact))
            .collect::<BTreeMap<_, _>>();
        let known_sources = index
            .sources
            .into_iter()
            .map(|source| (source.source.clone(), source))
            .collect::<BTreeMap<_, _>>();
        let ingested = self
            .try_direct(&mut direct::Request {
                id,
                source_root,
                ordered: &ordered,
                copy_original,
                selections,
                known_artifacts: &mut known_artifacts,
                known_sources: &known_sources,
                cancel,
            })?
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyMappedSourceDecoderUnavailable,
            ))?;
        if let Some(reader) = &self.engine.source_evidence_reader {
            let hashes = ingested
                .iter()
                .map(|(_, hash)| hash.clone())
                .collect::<Vec<_>>();
            reader.authorize_local_root(id, source_root, &hashes).map_err(|error| AppError::Storage(
                format!("Evidence ingestion committed, but original-record access is unavailable: {error}. Use indexed queries or explicitly select originals with /verify <source-root>")
            ))?;
        }
        Ok(ingested)
    }
}

fn invalid_manifest() -> AppError {
    AppError::Policy("invalid signed source or Parquet manifest".into())
}
