use super::{AppError, AuditLog, CaseId, LocalStore, Repository, storage};
use irmind_app::{SignedOperation, seal_challenge, sha256};
mod entries;

struct CatalogContents {
    artifacts: Option<Vec<ParquetArtifact>>,
    has_legacy: bool,
    source_names: std::collections::BTreeMap<String, String>,
}

use irmind_domain::{AuditEventKind, EvidenceHash, ParquetArtifact, SealedParquetMigrationV1};

pub(crate) struct CachedCatalog {
    seq: u64,
    hash: [u8; 32],
    operation_seq: u64,
    operation_hash: [u8; 32],
    data_version: u64,
    artifacts: Option<Vec<ParquetArtifact>>,
    has_legacy: bool,
    source_names: std::collections::BTreeMap<String, String>,
}

impl LocalStore {
    pub(super) fn query_catalog(&self, id: &CaseId) -> Result<super::QueryCatalog, AppError> {
        self.signed_parquet_artifacts(id)?;
        let cache = self.graph_catalog.lock().map_err(storage)?;
        let data = cache.get(id).ok_or(AppError::InvalidChain(0))?;
        if data.has_legacy {
            return Err(AppError::Policy("derived graph is unavailable until legacy evidence is migrated to Parquet; the signed case chain remains accessible".into()));
        }
        Ok(super::QueryCatalog {
            artifacts: data.artifacts.clone().unwrap_or_default(),
            source_names: data.source_names.clone(),
        })
    }

    fn graph_data_version(&self) -> Result<u64, AppError> {
        self.conn()?
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .map_err(storage)
    }

    pub(crate) fn signed_parquet_artifacts(
        &self,
        id: &CaseId,
    ) -> Result<Option<Vec<ParquetArtifact>>, AppError> {
        let last = self.last_entry(id)?.ok_or(AppError::InvalidChain(0))?;
        let operation = self.last_operation(id)?;
        let operation_seq = operation.as_ref().map_or(0, |entry| entry.seq);
        let operation_hash = operation.map_or([0; 32], |entry| entry.hash);
        let data_version = self.graph_data_version()?;
        if let Some(cached) = self.graph_catalog.lock().map_err(storage)?.get(id)
            && cached.seq == last.seq
            && cached.hash == last.hash
            && cached.operation_seq == operation_seq
            && cached.operation_hash == operation_hash
            && cached.data_version == data_version
        {
            return Ok(cached.artifacts.clone());
        }
        let case = self.get_case(id)?;
        let (operations, seal_hash) = if case.sealed {
            let seal = self
                .case_seal(id)?
                .ok_or(AppError::InvalidChain(last.seq))?;
            if last.kind != AuditEventKind::CaseSealed
                || seal.hash != last.hash
                || seal.seq != last.seq
                || seal.public_key != last.public_key
            {
                return Err(AppError::InvalidChain(last.seq));
            }
            crate::signing::verify_signature(
                &seal.public_key,
                &seal_challenge(id, seal.seq, &seal.hash, &last.payload),
                &seal.sig,
            )?;
            (self.operations(id)?, Some(seal.hash))
        } else {
            (Vec::new(), None)
        };
        let CatalogContents {
            artifacts: selected,
            has_legacy,
            source_names,
        } = {
            let entries = self.entries(id)?;
            self.verify_installed_mapping_metadata(&entries)?;
            collect_signed_artifacts(&entries, operations, seal_hash, id, &last)?
        };
        self.graph_catalog.lock().map_err(storage)?.insert(
            id.clone(),
            CachedCatalog {
                seq: last.seq,
                hash: last.hash,
                operation_seq,
                operation_hash,
                data_version,
                artifacts: selected.clone(),
                has_legacy,
                source_names,
            },
        );
        Ok(selected)
    }
}

fn collect_signed_artifacts(
    entries: &[irmind_app::SignedEntry],
    operations: Vec<SignedOperation>,
    seal_hash: Option<[u8; 32]>,
    id: &CaseId,
    last: &irmind_app::SignedEntry,
) -> Result<CatalogContents, AppError> {
    let mut state = entries::SignedSources::default();
    let mut previous = [0u8; 32];
    let mut seen = 0u64;
    let mut analyst_key = None;
    for (index, entry) in entries.iter().enumerate() {
        if entry.seq != index as u64 + 1
            || entry.case_id != id.as_str()
            || entry.prev != previous
            || irmind_app::sha256(&entry.canonical()) != entry.hash
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        crate::signing::verify_signature(&entry.public_key, &entry.hash, &entry.sig)?;
        check_analyst_key(entry, &mut analyst_key)?;
        previous = entry.hash;
        seen = entry.seq;
        state.accept(entry)?;
    }
    state.artifacts = irmind_app::artifact_catalog(entries)?.active;
    // Copied sources predating manifests retain their signed hash identity.
    for artifact in &state.artifacts {
        if artifact.precise_metadata().is_some() {
            for hash in artifact.source_hashes() {
                state
                    .source_names
                    .entry(hash.as_str().into())
                    .or_insert_with(|| hash.as_str().into());
            }
        }
    }
    if seen != last.seq || previous != last.hash {
        return Err(AppError::InvalidChain(last.seq));
    }
    if let Some(seal_hash) = seal_hash {
        collect_operational_artifacts(
            operations,
            seal_hash,
            id,
            analyst_key.as_deref(),
            &state.legacy_hashes,
            &mut state.artifacts,
        )?;
    }
    let converted = state
        .artifacts
        .iter()
        .flat_map(|a| a.source_hashes().iter())
        .cloned()
        .collect();
    let has_legacy = !state.legacy_hashes.is_subset(&converted);
    let selected = select_active_artifacts(
        state.artifacts,
        &state.legacy_hashes,
        &state.new_source_hashes,
        !state.new_source_hashes.is_empty(),
    )?;
    Ok(CatalogContents {
        artifacts: selected,
        has_legacy,
        source_names: state.source_names,
    })
}

fn check_analyst_key(
    entry: &irmind_app::SignedEntry,
    key: &mut Option<Vec<u8>>,
) -> Result<(), AppError> {
    if entry.actor == irmind_domain::Actor::Analyst {
        if key
            .as_ref()
            .is_some_and(|previous| previous != &entry.public_key)
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        *key = Some(entry.public_key.clone());
    }
    Ok(())
}

fn collect_operational_artifacts(
    operations: Vec<SignedOperation>,
    seal_hash: [u8; 32],
    id: &CaseId,
    analyst_key: Option<&[u8]>,
    legacy_hashes: &std::collections::BTreeSet<EvidenceHash>,
    artifacts: &mut Vec<ParquetArtifact>,
) -> Result<(), AppError> {
    let mut previous = [0; 32];
    for (index, operation) in operations.into_iter().enumerate() {
        if operation.case_id != id.as_str()
            || operation.seq != index as u64 + 1
            || operation.prev != previous
            || sha256(&operation.canonical()) != operation.hash
        {
            return Err(AppError::InvalidChain(operation.seq));
        }
        crate::signing::verify_signature(&operation.public_key, &operation.hash, &operation.sig)?;
        if let Some(record) = SealedParquetMigrationV1::decode(&operation.operation)
            .map_err(|_| AppError::InvalidChain(operation.seq))?
        {
            if operation.actor != irmind_domain::Actor::Analyst
                || Some(operation.public_key.as_slice()) != analyst_key
                || record.seal_hash != seal_hash
                || record.artifact.source_hashes.len() != 1
                || !legacy_hashes.contains(&record.artifact.source_hashes[0])
                || artifacts
                    .iter()
                    .any(|item| item.path() == record.artifact.path)
            {
                return Err(AppError::InvalidChain(operation.seq));
            }
            artifacts.push(record.artifact.into());
        }
        previous = operation.hash;
    }
    Ok(())
}

fn select_active_artifacts(
    mut artifacts: Vec<ParquetArtifact>,
    legacy_hashes: &std::collections::BTreeSet<EvidenceHash>,
    new_source_hashes: &std::collections::BTreeSet<EvidenceHash>,
    new_sources: bool,
) -> Result<Option<Vec<ParquetArtifact>>, AppError> {
    let converted = artifacts
        .iter()
        .flat_map(|artifact: &ParquetArtifact| artifact.source_hashes().iter())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if !legacy_hashes.is_subset(&converted) {
        artifacts.retain(|artifact| {
            artifact
                .source_hashes()
                .iter()
                .any(|hash| new_source_hashes.contains(hash))
        });
    }
    let covered = artifacts
        .iter()
        .filter(|artifact| artifact.source_hashes().len() > 1)
        .flat_map(|artifact| {
            artifact
                .source_hashes()
                .iter()
                .map(|hash| (artifact.compaction_key(), hash.clone()))
        })
        .collect::<std::collections::BTreeSet<_>>();
    artifacts.retain(|artifact| {
        matches!(artifact, ParquetArtifact::V3(_))
            || artifact.source_hashes().len() > 1
            || !covered.contains(&(
                artifact.compaction_key(),
                artifact.source_hashes()[0].clone(),
            ))
    });
    if new_sources && artifacts.is_empty() {
        Err(AppError::InvalidChain(0))
    } else if artifacts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(artifacts))
    }
}
