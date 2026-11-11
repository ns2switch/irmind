use super::{AppError, ParquetArtifact};

pub(super) fn validate_sources(
    sources: &[ParquetArtifact],
) -> Result<Vec<ParquetArtifact>, AppError> {
    if !(2..=128).contains(&sources.len()) {
        return Err(AppError::Policy(
            "Parquet compaction requires 2–128 sources".into(),
        ));
    }
    super::mapped::validate(sources)?;
    Ok(sources.to_vec())
}
