use super::{AppError, AuditLog, CaseId, LocalStore, Repository, storage};
use irmind_app::{SignedOperation, seal_challenge, sha256};
use std::collections::BTreeMap;

struct CatalogContents {
    artifacts: Option<Vec<ParquetArtifact>>,
    source_names: std::collections::BTreeMap<String, String>,
}

use irmind_domain::{AuditEventKind, ParquetArtifact, SourceManifestV2};

pub(crate) struct CachedCatalog {
    seq: u64,
    hash: [u8; 32],
    operation_seq: u64,
    operation_hash: [u8; 32],
    data_version: u64,
    artifacts: Option<Vec<ParquetArtifact>>,
    source_names: std::collections::BTreeMap<String, String>,
}

impl LocalStore {
    pub(crate) fn query_catalog(&self, id: &CaseId) -> Result<super::QueryCatalog, AppError> {
        self.signed_parquet_artifacts(id)?;
        let cache = self.graph_catalog.lock().map_err(storage)?;
        let data = cache.get(id).ok_or(AppError::InvalidChain(0))?;
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
        let operations = if case.sealed {
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
            self.operations(id)?
        } else {
            Vec::new()
        };
        let CatalogContents {
            artifacts: selected,
            source_names,
        } = {
            let entries = self.entries(id)?;
            self.verify_installed_mapping_metadata(&entries)?;
            collect_signed_artifacts(&entries, operations, id, &last)?
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
                source_names,
            },
        );
        Ok(selected)
    }
}

fn collect_signed_artifacts(
    entries: &[irmind_app::SignedEntry],
    operations: Vec<SignedOperation>,
    id: &CaseId,
    last: &irmind_app::SignedEntry,
) -> Result<CatalogContents, AppError> {
    let mut source_names = BTreeMap::new();
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
        if entry.kind == AuditEventKind::SourceManifestV2 {
            record_source_name(entry, &mut source_names)?;
        }
    }
    if seen != last.seq || previous != last.hash {
        return Err(AppError::InvalidChain(last.seq));
    }
    verify_operations(id, operations)?;
    let selected = irmind_app::artifact_catalog(entries)?.active;
    let covered = selected
        .iter()
        .flat_map(ParquetArtifact::source_hashes)
        .map(irmind_domain::EvidenceHash::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if source_names
        .keys()
        .any(|hash| !covered.contains(hash.as_str()))
    {
        return Err(AppError::InvalidChain(last.seq));
    }
    Ok(CatalogContents {
        artifacts: (!selected.is_empty()).then_some(selected),
        source_names,
    })
}

fn record_source_name(
    entry: &irmind_app::SignedEntry,
    names: &mut BTreeMap<String, String>,
) -> Result<(), AppError> {
    let source = SourceManifestV2::decode(&entry.payload)
        .map_err(|_| AppError::InvalidChain(entry.seq))?
        .source;
    names
        .entry(source.sha256.as_str().into())
        .and_modify(|current| {
            if source.source < *current {
                current.clone_from(&source.source);
            }
        })
        .or_insert(source.source);
    Ok(())
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

fn verify_operations(id: &CaseId, operations: Vec<SignedOperation>) -> Result<(), AppError> {
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
        previous = operation.hash;
    }
    Ok(())
}
