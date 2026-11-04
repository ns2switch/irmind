use crate::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, Engine, LargeCaseStore,
    StreamingEventParser, sha256,
};

mod manifest;
mod migrate_v2;
mod migration;
mod source_event;
mod verification;
use irmind_domain::{
    EvidenceHash, ParquetArtifact, ParserSelectionMode, SourceManifestV1, SourceManifestV2,
};
use manifest::select_sources;
pub(crate) use manifest::{read_manifest_index, read_sealed_artifacts};
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
    pub format_sample_sha256: [u8; 32],
}

impl LargeCaseUseCases<'_, '_> {
    /// Sign bounded, reproducible Parquet bundles after ingest. Historical
    /// single-source artifacts remain available for full reconstruction.
    pub fn compact_case(&self, id: &CaseId, cancel: &CancellationToken) -> Result<usize, AppError> {
        self.engine.require_attended_analyst("compact Parquet")?;
        let _case_lock = self.engine.repo.lock_case(id)?;
        if self.engine.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.engine.verify_ingest_checkpoint(id, cancel)?;
        let index = crate::artifact_catalog(&self.engine.audit_log.entries(id)?)?.active;
        let mut known = index
            .iter()
            .map(|artifact| (artifact.path().to_owned(), artifact.clone()))
            .collect::<BTreeMap<_, _>>();
        let covered = index
            .iter()
            .filter(|artifact| artifact.source_hashes().len() > 1)
            .flat_map(|artifact| {
                artifact
                    .source_hashes()
                    .iter()
                    .map(|hash| (artifact.compaction_key(), hash.clone()))
            })
            .collect::<BTreeSet<_>>();
        let mut groups: BTreeMap<Vec<u8>, Vec<ParquetArtifact>> = BTreeMap::new();
        for artifact in index {
            if !matches!(&artifact, ParquetArtifact::V2(v) if !v.superseded_hashes.is_empty())
                && artifact.source_hashes().len() == 1
                && (artifact.parser_version() == "json-stream-v2"
                    || matches!(artifact, ParquetArtifact::V2(_)))
                && !covered.contains(&(
                    artifact.compaction_key(),
                    artifact.source_hashes()[0].clone(),
                ))
            {
                groups
                    .entry(artifact.compaction_key())
                    .or_default()
                    .push(artifact);
            }
        }
        let mut compacted = 0usize;
        for artifacts in groups.values_mut() {
            artifacts.sort_by(|left, right| left.source_hashes()[0].cmp(&right.source_hashes()[0]));
            for chunk in artifacts.chunks(128) {
                if chunk.len() < 2 {
                    continue;
                }
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let bundle = self.store.compact_artifacts(id, chunk, cancel)?;
                self.store.verify_artifact(id, &bundle, cancel)?;
                self.audit_artifact(id, bundle, &mut known)?;
                compacted += 1;
            }
        }
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
        let mut known_sources = index
            .sources
            .into_iter()
            .map(|source| (source.source.clone(), source))
            .collect::<BTreeMap<_, _>>();
        let mut ingested = Vec::with_capacity(ordered.len());
        for paths in ordered.chunks(4) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let mut pending = Vec::new();
            for path in paths {
                if let Some(existing) = known_sources.get(path) {
                    if copy_original && !existing.copied {
                        return Err(AppError::Policy(
                            "this source was signed without a copy; select a new source path"
                                .into(),
                        ));
                    }
                    self.store
                        .verify_local_source(source_root, existing, cancel)?;
                    ingested.push((path.clone(), existing.sha256.clone()));
                } else {
                    pending.push(path);
                }
            }
            let prepared = self.prepare_sources_parallel(
                id,
                source_root,
                &pending,
                copy_original,
                &known_artifacts,
                cancel,
            )?;
            for (path, source) in pending.iter().zip(prepared) {
                known_sources.insert((*path).clone(), source.manifest.clone());
                let hash = self.sign_prepared_with_selection(
                    id,
                    source,
                    selections.get(*path),
                    cancel,
                    &mut known_artifacts,
                )?;
                ingested.push(((*path).clone(), hash));
            }
        }
        ingested.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(ingested)
    }

    fn prepare_sources_parallel(
        &self,
        id: &CaseId,
        source_root: &Path,
        pending: &[&String],
        copy_original: bool,
        known: &BTreeMap<String, ParquetArtifact>,
        cancel: &CancellationToken,
    ) -> Result<Vec<crate::PreparedSource>, AppError> {
        let paths = pending.iter().map(|p| (*p).clone()).collect::<Vec<_>>();
        let committed = known.values().cloned().collect::<Vec<_>>();
        self.store.prepare_local_batch(
            crate::LocalBatchRequest {
                case_id: id,
                source_root,
                relative_paths: &paths,
                copy_original,
                parser: self.parser,
                committed_artifacts: &committed,
                limits: crate::PartitionLimits::default(),
            },
            cancel,
        )
    }

    pub(crate) fn sign_prepared_with_selection(
        &self,
        id: &CaseId,
        prepared: crate::PreparedSource,
        selection: Option<&ParserSelection>,
        cancel: &CancellationToken,
        known_artifacts: &mut BTreeMap<String, ParquetArtifact>,
    ) -> Result<EvidenceHash, AppError> {
        if prepared
            .artifacts
            .iter()
            .any(|a| matches!(a, ParquetArtifact::V2(_)))
            && selection.is_none()
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyPreciseArtifactsRequireParserSelection,
            ));
        }
        if prepared.records == 0 || prepared.artifacts.is_empty() {
            return Err(AppError::Policy(
                "source produced no Parquet records".into(),
            ));
        }
        let source_hash = prepared.manifest.sha256.clone();
        for artifact in &prepared.artifacts {
            if artifact.source_hashes() != [source_hash.clone()] {
                return Err(AppError::Policy("Parquet source linkage is invalid".into()));
            }
            if known_artifacts.values().any(|old| {
                !old.same_generation(artifact)
                    && old.source_hashes().binary_search(&source_hash).is_ok()
            }) {
                return Err(AppError::Fixed(
                    crate::FixedAppError::PolicyArtifactVersionRequiresMigration,
                ));
            }
            self.store.verify_artifact(id, artifact, cancel)?;
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let source_event = self.source_event(&prepared, selection)?;
        let mut events = vec![(AuditOrigin::System, source_event.0, source_event.1)];
        let mut new_artifacts = Vec::new();
        let mut new_paths = BTreeSet::new();
        for artifact in prepared.artifacts {
            if let Some(previous) = known_artifacts.get(artifact.path()) {
                if previous != &artifact {
                    return Err(AppError::EvidenceMismatch(artifact.path().to_owned()));
                }
                continue;
            }
            if !new_paths.insert(artifact.path().to_owned()) {
                return Err(invalid_manifest());
            }
            events.push((
                AuditOrigin::System,
                artifact.audit_kind(),
                artifact.encode().map_err(|_| invalid_manifest())?,
            ));
            new_artifacts.push(artifact);
        }
        self.engine.audit_batch(id, &events)?;
        known_artifacts.extend(
            new_artifacts
                .into_iter()
                .map(|artifact| (artifact.path().to_owned(), artifact)),
        );
        Ok(source_hash)
    }
}

fn invalid_manifest() -> AppError {
    AppError::Policy("invalid signed source or Parquet manifest".into())
}
