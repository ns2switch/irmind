use super::super::{
    AppError, CancellationToken, ParquetArtifact, Path, StagedArtifact, invalid_source, storage,
};
use std::collections::BTreeMap;

/// A source can revisit a partition after writer-pool eviction. Merge its
/// bounded segments before publication, leaving one artifact per family/bucket.
pub(super) fn consolidate(
    dir: &Path,
    staged: Vec<StagedArtifact>,
    cancel: &CancellationToken,
    profile: Option<&super::super::ParquetProfile>,
    normalized_bytes: u64,
) -> Result<Vec<StagedArtifact>, AppError> {
    let mut temporary_bytes = staged.iter().map(|s| s.manifest.size()).sum::<u64>();
    if let Some(p) = profile {
        p.record_staging_peak(normalized_bytes.saturating_add(temporary_bytes));
    }
    let mut groups: BTreeMap<Vec<u8>, Vec<StagedArtifact>> = BTreeMap::new();
    for artifact in staged {
        let mut key = artifact.manifest.compaction_key();
        if let Some(route) = super::super::mapped::route_from_path(artifact.manifest.path())? {
            key.extend_from_slice(route.as_bytes());
        }
        groups.entry(key).or_default().push(artifact);
    }
    let mut out = Vec::new();
    for parts in groups.into_values() {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if parts.len() == 1 {
            out.extend(parts);
            continue;
        }
        let merged = merge_parts(dir, &parts, cancel)?;
        temporary_bytes = temporary_bytes.saturating_add(merged.manifest.size());
        if let Some(p) = profile {
            p.record_staging_peak(normalized_bytes.saturating_add(temporary_bytes));
        }
        temporary_bytes =
            temporary_bytes.saturating_sub(parts.iter().map(|p| p.manifest.size()).sum::<u64>());
        out.push(merged);
    }
    out.sort_by(|a, b| a.manifest.path().cmp(b.manifest.path()));
    Ok(out)
}

fn merge_parts(
    dir: &Path,
    parts: &[StagedArtifact],
    cancel: &CancellationToken,
) -> Result<StagedArtifact, AppError> {
    let Some(ParquetArtifact::V2(first)) = parts.first().map(|p| &p.manifest) else {
        return Err(invalid_source());
    };
    if first.source_hashes.len() != 1
        || parts
            .iter()
            .any(|p| p.manifest.source_hashes() != first.source_hashes)
    {
        return Err(invalid_source());
    }
    let temporary = tempfile::Builder::new()
        .prefix("irmind-normalized-")
        .tempfile_in(dir.join("spool"))
        .map_err(storage)?;
    irmind_fs::private_file(temporary.path()).map_err(storage)?;
    let paths = parts
        .iter()
        .map(|p| (p.manifest.path().to_owned(), p.temporary.clone()))
        .collect();
    let manifests = parts.iter().map(|p| p.manifest.clone()).collect::<Vec<_>>();
    let (size, hash) = super::super::compact::write_inputs(
        dir,
        temporary.path(),
        &manifests,
        temporary.as_file().try_clone().map_err(storage)?,
        cancel,
        &paths,
    )?;
    let mut manifest = first.clone();
    manifest.path = format!(
        "{}/{}.merged.{}.parquet",
        first
            .partition
            .path_prefix()
            .map_err(|_| invalid_source())?
            .trim_end_matches('/'),
        first.source_hashes[0].as_str(),
        first.schema.as_str()
    );
    if let Some(route) = super::super::mapped::route_from_path(&first.path)? {
        manifest.path = format!(
            "{}.map-{route}.parquet",
            manifest
                .path
                .strip_suffix(".parquet")
                .ok_or_else(invalid_source)?
        );
    }
    manifest.size = size;
    manifest.sha256 = irmind_domain::EvidenceHash::parse(&irmind_app::hex(&hash))
        .map_err(|_| invalid_source())?;
    manifest.validate().map_err(|_| invalid_source())?;
    let (file, path) = temporary.keep().map_err(storage)?;
    drop(file);
    Ok(StagedArtifact {
        rows: parts
            .iter()
            .try_fold(0u64, |sum, part| sum.checked_add(part.rows?)),
        temporary: path,
        manifest: manifest.into(),
    })
}
