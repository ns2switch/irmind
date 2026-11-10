use super::{
    AppError, AuditEventKind, BTreeMap, BTreeSet, EvidenceHash, ManifestIndex, ParquetArtifact,
    SourceCheckMode, SourceManifestV1, sha256,
};
use irmind_domain::SourceManifestV2;

pub(crate) fn read_manifest_index(
    entries: &[crate::SignedEntry],
) -> Result<ManifestIndex, AppError> {
    crate::artifact_catalog(entries)?;
    let mut sources = Vec::new();
    let mut artifacts = Vec::new();
    let mut source_hashes = BTreeSet::new();
    let mut source_names = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    let mut parser_selections = BTreeMap::new();
    for entry in entries {
        match entry.kind {
            AuditEventKind::SourceManifestV2 => {
                record_parser_manifest(
                    entry,
                    &mut source_names,
                    &mut source_hashes,
                    &mut sources,
                    &mut parser_selections,
                )?;
            }
            AuditEventKind::ParquetArtifactV3 => {
                if entry.evidence.is_some() {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                let artifact = ParquetArtifact::decode(entry.kind, &entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if !artifact_paths.insert(artifact.path().to_owned()) {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                if artifact
                    .source_hashes()
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
    validate_manifest_links(entries, &sources, &artifacts, parser_selections)?;
    Ok(ManifestIndex { sources, artifacts })
}

fn validate_manifest_links(
    entries: &[crate::SignedEntry],
    sources: &[SourceManifestV1],
    artifacts: &[ParquetArtifact],
    parser_selections: BTreeMap<String, (SourceManifestV2, u64)>,
) -> Result<(), AppError> {
    let indexed: BTreeSet<_> = artifacts
        .iter()
        .flat_map(|artifact| artifact.source_hashes().iter())
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
    for (_, (selection, seq)) in parser_selections {
        if !artifacts.iter().any(|artifact| {
            (artifact.source_hashes().len() == 1
                || matches!(artifact, ParquetArtifact::V3(mapped)
                    if mapped.core().builder_version == irmind_domain::COMMON_EVENT_DIRECT_BUILDER))
                && artifact.source_hashes().contains(&selection.source.sha256)
                && artifact.parser_version() == selection.parser_version
        }) {
            return Err(AppError::InvalidChain(seq));
        }
    }
    Ok(())
}

fn record_parser_manifest(
    entry: &crate::SignedEntry,
    source_names: &mut BTreeSet<String>,
    source_hashes: &mut BTreeSet<EvidenceHash>,
    sources: &mut Vec<SourceManifestV1>,
    parser_selections: &mut BTreeMap<String, (SourceManifestV2, u64)>,
) -> Result<(), AppError> {
    if entry.evidence.is_some() {
        return Err(AppError::InvalidChain(entry.seq));
    }
    let selection =
        SourceManifestV2::decode(&entry.payload).map_err(|_| AppError::InvalidChain(entry.seq))?;
    let source = &selection.source;
    if !source_names.insert(source.source.clone())
        || parser_selections
            .insert(source.source.clone(), (selection.clone(), entry.seq))
            .is_some()
    {
        return Err(AppError::InvalidChain(entry.seq));
    }
    source_hashes.insert(source.sha256.clone());
    sources.push(source.clone());
    Ok(())
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

#[cfg(test)]
mod tests;
