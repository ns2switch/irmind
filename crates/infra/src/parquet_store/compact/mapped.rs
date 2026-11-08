use super::{AppError, ParquetArtifact, Path, StagedArtifact, fs, invalid_source, storage};
use irmind_domain::{EvidenceHash, ParquetArtifactV3, ParquetLayoutV1};
use std::collections::BTreeSet;

pub(super) fn parents(sources: &[ParquetArtifact]) -> Result<Vec<ParquetArtifactV3>, AppError> {
    sources
        .iter()
        .map(|source| match source {
            ParquetArtifact::V3(value) => Ok(value.clone()),
            _ => Err(invalid_source()),
        })
        .collect()
}
pub(super) fn validate(sources: &[ParquetArtifact]) -> Result<Vec<EvidenceHash>, AppError> {
    let parents = parents(sources)?;
    let bindings = ParquetLayoutV1::preserved_bindings(&parents).map_err(|_| invalid_source())?;
    let mut paths = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for value in &parents {
        if !paths.insert(value.core().path.as_str())
            || !ids.insert(value.identity().map_err(|_| invalid_source())?)
        {
            return Err(invalid_source());
        }
    }
    Ok(bindings
        .into_iter()
        .map(|b| b.input().source().clone())
        .collect())
}
pub(super) fn stage(
    case_dir: &Path,
    sources: &[ParquetArtifact],
) -> Result<StagedArtifact, AppError> {
    let parents = parents(sources)?;
    let metadata = ParquetLayoutV1::replacement(&parents, 0, EvidenceHash::from_bytes([0; 32]))
        .map_err(|_| invalid_source())?;
    let target = case_dir.join(&metadata.core().path);
    let directory = target.parent().ok_or_else(invalid_source)?;
    fs::create_dir_all(directory).map_err(storage)?;
    irmind_fs::private_dir(directory).map_err(storage)?;
    let name = target
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(invalid_source)?;
    let temporary = directory.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
    Ok(StagedArtifact {
        rows: None,
        temporary,
        manifest: metadata.into(),
    })
}
