use super::{
    AppError, AuditEventKind, BTreeMap, BTreeSet, EvidenceHash, ManifestIndex, ParquetArtifactV1,
    SourceCheckMode, SourceManifestV1, sha256,
};
use crate::SignedOperation;
use irmind_domain::{Actor, SealedParquetMigrationV1};

pub(crate) fn read_manifest_index(
    entries: &[crate::SignedEntry],
) -> Result<ManifestIndex, AppError> {
    let mut sources = Vec::new();
    let mut artifacts = Vec::new();
    let mut source_hashes = BTreeSet::new();
    let mut source_names = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    for entry in entries {
        match entry.kind {
            AuditEventKind::EvidenceIngested | AuditEventKind::GraphIndexed => {
                let hash = entry
                    .evidence
                    .as_deref()
                    .ok_or(AppError::InvalidChain(entry.seq))?;
                source_hashes.insert(
                    EvidenceHash::parse(hash).map_err(|_| AppError::InvalidChain(entry.seq))?,
                );
            }
            AuditEventKind::SourceManifestV1 => {
                if entry.evidence.is_some() {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                let source = SourceManifestV1::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if !source_names.insert(source.source.clone()) {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                source_hashes.insert(source.sha256.clone());
                sources.push(source);
            }
            AuditEventKind::ParquetArtifactV1 => {
                if entry.evidence.is_some() {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                let artifact = ParquetArtifactV1::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if !artifact_paths.insert(artifact.path.clone()) {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                if artifact
                    .source_hashes
                    .iter()
                    .any(|hash| !source_hashes.contains(hash))
                {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                artifacts.push(artifact);
            }
            _ => {}
        }
    }
    let indexed: BTreeSet<_> = artifacts
        .iter()
        .flat_map(|artifact| artifact.source_hashes.iter())
        .cloned()
        .collect();
    let manifest_hashes = sources
        .iter()
        .map(|source| source.sha256.clone())
        .collect::<BTreeSet<_>>();
    if !manifest_hashes.is_subset(&indexed) {
        return Err(AppError::InvalidChain(
            entries.last().map_or(0, |entry| entry.seq),
        ));
    }
    Ok(ManifestIndex { sources, artifacts })
}

pub(crate) fn read_sealed_artifacts(
    entries: &[crate::SignedEntry],
    operations: &[SignedOperation],
    seal_hash: [u8; 32],
) -> Result<Vec<ParquetArtifactV1>, AppError> {
    let legacy = entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::GraphIndexed)
        .filter_map(|entry| entry.evidence.as_deref())
        .map(EvidenceHash::parse)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| AppError::InvalidChain(0))?;
    let mut paths = read_manifest_index(entries)?
        .artifacts
        .into_iter()
        .map(|artifact| artifact.path)
        .collect::<BTreeSet<_>>();
    let mut artifacts = Vec::new();
    for operation in operations {
        let Some(record) = SealedParquetMigrationV1::decode(&operation.operation)
            .map_err(|_| AppError::InvalidChain(operation.seq))?
        else {
            continue;
        };
        if operation.actor != Actor::Analyst
            || record.seal_hash != seal_hash
            || record.artifact.source_hashes.len() != 1
            || !legacy.contains(&record.artifact.source_hashes[0])
            || !paths.insert(record.artifact.path.clone())
        {
            return Err(AppError::InvalidChain(operation.seq));
        }
        artifacts.push(record.artifact);
    }
    Ok(artifacts)
}

pub(super) fn select_sources(
    sources: Vec<SourceManifestV1>,
    mode: SourceCheckMode,
) -> Result<Vec<SourceManifestV1>, AppError> {
    match mode {
        SourceCheckMode::Full => Ok(sources),
        SourceCheckMode::Sample(count) => {
            if count == 0 || count > sources.len() {
                return Err(AppError::Policy(
                    "invalid source verification sample size".into(),
                ));
            }
            let nonce = uuid::Uuid::new_v4();
            let mut ranked = BTreeMap::new();
            for (index, source) in sources.into_iter().enumerate() {
                let mut bytes = nonce.as_bytes().to_vec();
                bytes.extend_from_slice(source.sha256.as_str().as_bytes());
                bytes.extend_from_slice(&(index as u64).to_be_bytes());
                ranked.insert(sha256(&bytes), source);
            }
            Ok(ranked.into_values().take(count).collect())
        }
    }
}
