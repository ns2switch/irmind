use super::super::{AppError, CaseId, ParquetArtifact, ParquetStore, invalid_source, storage};
use irmind_app::source_mapping::{
    DecodedSourceCommitmentV1, MappedArtifactProjection, PreparedMappingSource,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;

impl ParquetStore {
    pub(in crate::parquet_store) fn prepare_mapping_projection(
        &self,
        input: Option<DecodedSourceCommitmentV1>,
        artifacts: &[ParquetArtifact],
        id: &CaseId,
    ) -> Result<Option<PreparedMappingSource>, AppError> {
        let Some(input) = input else { return Ok(None) };
        let catalog = self.mapping_catalog.as_deref().ok_or_else(invalid_source)?;
        let routes = super::decode::projection_routes(catalog)?;
        let mut projections = Vec::new();
        let dir = self.case_dir(id)?;
        for artifact in artifacts {
            let ParquetArtifact::V2(core) = artifact else {
                return Err(invalid_source());
            };
            let route = route_from_path(&core.path)?.ok_or_else(invalid_source)?;
            let mapping = routes
                .iter()
                .find(|(_, value)| value.as_str() == route)
                .map(|(id, _)| id.clone())
                .ok_or_else(invalid_source)?;
            let file =
                irmind_fs::open_regular_no_follow(&dir, Path::new(&core.path)).map_err(storage)?;
            let reader = ParquetRecordBatchReaderBuilder::try_new(file).map_err(storage)?;
            super::super::format::validate_schema(artifact, reader.schema())?;
            let rows =
                u64::try_from(reader.metadata().file_metadata().num_rows()).map_err(storage)?;
            if rows > 0 {
                projections.push(MappedArtifactProjection::try_new(
                    core.clone(),
                    mapping,
                    rows,
                )?);
            }
        }
        PreparedMappingSource::try_new(
            input,
            catalog
                .snapshots()
                .map_err(irmind_app::source_mapping::MappingError::into_app)?,
            projections,
        )
        .map(Some)
    }
}

pub(in crate::parquet_store) fn route_from_path(path: &str) -> Result<Option<&str>, AppError> {
    let Some((_, route)) = path.rsplit_once(".map-") else {
        return Ok(None);
    };
    let route = route.strip_suffix(".parquet").ok_or_else(invalid_source)?;
    if route.len() != 64
        || !route
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_source());
    }
    Ok(Some(route))
}
