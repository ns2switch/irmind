use super::{
    AppError, CancellationToken, CaseId, EvidenceHash, File, OpenOptions, ParquetArtifact,
    ParquetStore, Path, StagedArtifact, fs, invalid_source, storage,
};
use arrow::compute::{SortColumn, lexsort_to_indices, take};
use arrow::record_batch::RecordBatch;
use parquet::arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder};
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use parquet::schema::types::ColumnPath;
use std::io::{Seek as _, SeekFrom};
mod manifest;
use manifest::validate_sources;

impl ParquetStore {
    pub(super) fn compact_signed_sources(
        &self,
        id: &CaseId,
        sources: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<ParquetArtifact, AppError> {
        let (mut ordered, hashes) = validate_sources(sources)?;
        ordered.sort_by(|left, right| left.path().cmp(right.path()));
        let first = ordered.first().ok_or_else(invalid_source)?;
        let case_dir = self.case_dir(id)?;
        let mut staged = manifest::stage(&case_dir, first, hashes)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let output = options.open(&staged.temporary).map_err(storage)?;
        irmind_fs::private_file(&staged.temporary).map_err(storage)?;
        let (size, digest) = write_compact(&case_dir, &staged.temporary, &ordered, output, cancel)?;
        match &mut staged.manifest {
            ParquetArtifact::V1(v) => {
                v.size = size;
                v.sha256 =
                    EvidenceHash::parse(&irmind_app::hex(&digest)).map_err(|_| invalid_source())?;
            }
            ParquetArtifact::V2(v) => {
                v.size = size;
                v.sha256 =
                    EvidenceHash::parse(&irmind_app::hex(&digest)).map_err(|_| invalid_source())?;
            }
        }
        self.finish_artifacts(id, vec![staged])?
            .pop()
            .ok_or_else(invalid_source)
    }
}

fn write_compact(
    case_dir: &Path,
    output_path: &Path,
    sources: &[ParquetArtifact],
    output: File,
    cancel: &CancellationToken,
) -> Result<(u64, [u8; 32]), AppError> {
    write_inputs(
        case_dir,
        output_path,
        sources,
        output,
        cancel,
        &std::collections::BTreeMap::new(),
    )
}

pub(super) fn write_inputs(
    case_dir: &Path,
    output_path: &Path,
    sources: &[ParquetArtifact],
    output: File,
    cancel: &CancellationToken,
    temporary_paths: &std::collections::BTreeMap<String, std::path::PathBuf>,
) -> Result<(u64, [u8; 32]), AppError> {
    let schema = sources.first().ok_or_else(invalid_source)?.schema_version();
    let optimized = matches!(
        schema,
        "irmind-entities-v2"
            | "irmind-coobservations-v1"
            | "irmind-entities-v3"
            | "irmind-coobservations-v2"
            | "irmind-entities-v4"
            | "irmind-coobservations-v3"
    );
    let properties = compact_properties(optimized);
    let mut output = Some(output);
    let mut writer: Option<ArrowWriter<File>> = None;
    for source in sources {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let relative = temporary_paths.get(source.path()).map_or_else(
            || Ok(Path::new(source.path())),
            |path| path.strip_prefix(case_dir).map_err(|_| invalid_source()),
        )?;
        let mut check = irmind_fs::open_regular_no_follow(case_dir, relative).map_err(storage)?;
        let (digest, size) = ParquetStore::hash_reader(&mut check, cancel)?;
        if digest != super::parse_hash(source.sha256())? || size != source.size() {
            return Err(AppError::EvidenceMismatch(source.sha256().as_str().into()));
        }
        check.seek(SeekFrom::Start(0)).map_err(storage)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(check).map_err(storage)?;
        super::format::validate_schema(source, builder.schema().as_ref())?;
        // Record-batch readers expose only column metadata. Keep the validated
        // common schema metadata when constructing a replacement file; old
        // builders retain their historical construction unchanged.
        let common_schema = matches!(source, ParquetArtifact::V2(v) if v.schema.is_common())
            .then(|| builder.schema().clone());
        let reader = builder.with_batch_size(8192).build().map_err(storage)?;
        for batch in reader {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let batch = batch.map_err(storage)?;
            let batch = if optimized {
                sort_entity_batch(&batch)?
            } else {
                batch
            };
            if writer.is_none() {
                writer = Some(
                    ArrowWriter::try_new(
                        output.take().ok_or_else(invalid_source)?,
                        common_schema.clone().unwrap_or_else(|| batch.schema()),
                        Some(properties.clone()),
                    )
                    .map_err(storage)?,
                );
            }
            writer
                .as_mut()
                .ok_or_else(invalid_source)?
                .write(&batch)
                .map_err(storage)?;
            if optimized {
                writer
                    .as_mut()
                    .ok_or_else(invalid_source)?
                    .flush()
                    .map_err(storage)?;
            }
        }
    }
    writer
        .ok_or_else(invalid_source)?
        .close()
        .map_err(storage)?;
    // Windows FlushFileBuffers requires a writable handle.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(output_path)
        .map_err(storage)?;
    file.sync_all().map_err(storage)?;
    let (digest, size) = ParquetStore::hash_reader(&mut file, cancel)?;
    Ok((size, digest))
}

fn sort_entity_batch(batch: &RecordBatch) -> Result<RecordBatch, AppError> {
    let keys = ["entity_kind", "entity_value", "source_hash", "record_index"]
        .iter()
        .map(|name| {
            batch
                .column_by_name(name)
                .cloned()
                .map(|values| SortColumn {
                    values,
                    options: None,
                })
                .ok_or_else(invalid_source)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let indices = lexsort_to_indices(&keys, None).map_err(storage)?;
    let columns = batch
        .columns()
        .iter()
        .map(|column| take(column, &indices, None).map_err(storage))
        .collect::<Result<Vec<_>, _>>()?;
    RecordBatch::try_new(batch.schema(), columns).map_err(storage)
}

fn compact_properties(optimized: bool) -> WriterProperties {
    let mut properties = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_max_row_group_row_count(Some(if optimized { 1024 } else { 8192 }));
    if optimized {
        properties = properties
            .set_column_bloom_filter_enabled(ColumnPath::from("entity_value"), true)
            .set_column_bloom_filter_fpp(ColumnPath::from("entity_value"), 0.01);
    }
    properties.build()
}
