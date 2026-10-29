use crate::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, Engine, LargeCaseStore,
    StreamingEventParser, sha256,
};

mod manifest;
mod migration;
mod verification;
use irmind_domain::{EvidenceHash, ParquetArtifactV1, SourceManifestV1};
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
    pub artifacts: Vec<ParquetArtifactV1>,
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
        let index = read_manifest_index(&self.engine.audit_log.entries(id)?)?;
        let mut known = index
            .artifacts
            .iter()
            .map(|artifact| (artifact.path.clone(), artifact.clone()))
            .collect::<BTreeMap<_, _>>();
        let covered = index
            .artifacts
            .iter()
            .filter(|artifact| artifact.source_hashes.len() > 1)
            .flat_map(|artifact| {
                artifact.source_hashes.iter().map(|hash| {
                    (
                        artifact.partition_date.clone(),
                        artifact.partition_account.clone(),
                        artifact.partition_region.clone(),
                        artifact.schema_version.clone(),
                        hash.clone(),
                    )
                })
            })
            .collect::<BTreeSet<_>>();
        let mut groups: BTreeMap<(String, String, String, String), Vec<ParquetArtifactV1>> =
            BTreeMap::new();
        for artifact in index.artifacts {
            if artifact.source_hashes.len() == 1
                && artifact.parser_version == "json-stream-v2"
                && !covered.contains(&(
                    artifact.partition_date.clone(),
                    artifact.partition_account.clone(),
                    artifact.partition_region.clone(),
                    artifact.schema_version.clone(),
                    artifact.source_hashes[0].clone(),
                ))
            {
                groups
                    .entry((
                        artifact.partition_date.clone(),
                        artifact.partition_account.clone(),
                        artifact.partition_region.clone(),
                        artifact.schema_version.clone(),
                    ))
                    .or_default()
                    .push(artifact);
            }
        }
        let mut compacted = 0usize;
        for artifacts in groups.values_mut() {
            artifacts.sort_by(|left, right| left.source_hashes[0].cmp(&right.source_hashes[0]));
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
            .map(|artifact| (artifact.path.clone(), artifact))
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
            let prepared = std::thread::scope(|scope| {
                let handles = pending
                    .iter()
                    .map(|path| {
                        scope.spawn(move || {
                            self.store.prepare_local(
                                id,
                                source_root,
                                path,
                                copy_original,
                                self.parser,
                                cancel,
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| {
                        handle.join().map_err(|_| {
                            AppError::Policy("source preparation worker failed".into())
                        })?
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;
            for (path, source) in pending.iter().zip(prepared) {
                known_sources.insert((*path).clone(), source.manifest.clone());
                let hash = self.sign_prepared(id, source, cancel, &mut known_artifacts)?;
                ingested.push(((*path).clone(), hash));
            }
        }
        ingested.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(ingested)
    }

    pub(crate) fn sign_prepared(
        &self,
        id: &CaseId,
        prepared: crate::PreparedSource,
        cancel: &CancellationToken,
        known_artifacts: &mut BTreeMap<String, ParquetArtifactV1>,
    ) -> Result<EvidenceHash, AppError> {
        if prepared.records == 0 || prepared.artifacts.is_empty() {
            return Err(AppError::Policy(
                "source produced no Parquet records".into(),
            ));
        }
        let source_hash = prepared.manifest.sha256.clone();
        for artifact in &prepared.artifacts {
            if artifact.source_hashes.as_slice() != [source_hash.clone()] {
                return Err(AppError::Policy("Parquet source linkage is invalid".into()));
            }
            self.store.verify_artifact(id, artifact, cancel)?;
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut events = vec![(
            AuditOrigin::System,
            AuditEventKind::SourceManifestV1,
            prepared.manifest.encode().map_err(|_| invalid_manifest())?,
        )];
        let mut new_artifacts = Vec::new();
        let mut new_paths = BTreeSet::new();
        for artifact in prepared.artifacts {
            if let Some(previous) = known_artifacts.get(&artifact.path) {
                if previous != &artifact {
                    return Err(AppError::EvidenceMismatch(artifact.path));
                }
                continue;
            }
            if !new_paths.insert(artifact.path.clone()) {
                return Err(invalid_manifest());
            }
            events.push((
                AuditOrigin::System,
                AuditEventKind::ParquetArtifactV1,
                artifact.encode().map_err(|_| invalid_manifest())?,
            ));
            new_artifacts.push(artifact);
        }
        self.engine.audit_batch(id, &events)?;
        known_artifacts.extend(
            new_artifacts
                .into_iter()
                .map(|artifact| (artifact.path.clone(), artifact)),
        );
        Ok(source_hash)
    }
}

fn invalid_manifest() -> AppError {
    AppError::Policy("invalid signed source or Parquet manifest".into())
}
