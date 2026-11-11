use super::{
    AppError, ArrayRef, ArrowWriter, BTreeMap, CancellationToken, Compression, EvidenceHash, File,
    OpenOptions, ParquetArtifact, ParquetStore, Path, PathBuf, RecordBatch, StringArray,
    UInt64Array, WriterProperties, fs, invalid_source, storage,
};
#[cfg(test)]
use irmind_app::GraphRecord;
use std::sync::Arc;

pub(super) mod common;
pub(in crate::parquet_store) mod direct;
pub(super) mod precise;
mod staged_time;
use parquet::schema::types::ColumnPath;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
pub(super) struct Partition {
    date: String,
    account: String,
    region: String,
    #[serde(skip)]
    scope: Option<irmind_domain::ArtifactPartitionV2>,
    segment: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mapping_route: Option<String>,
}

impl Partition {
    pub(in crate::parquet_store) fn mapping_route(&self) -> Option<&str> {
        self.mapping_route.as_deref()
    }
    pub(in crate::parquet_store) fn utc_date(&self) -> &str {
        &self.date
    }
    pub(in crate::parquet_store) fn with_scope(
        mut self,
        scope: irmind_domain::ArtifactPartitionV2,
        segment: u32,
    ) -> Self {
        self.scope = Some(scope);
        self.segment = segment;
        self
    }
}

mod row;
pub(super) use row::{RecordRow, raw_host, safe_partition};
pub(super) struct StagedArtifact {
    pub rows: Option<u64>,
    pub temporary: PathBuf,
    pub manifest: ParquetArtifact,
}

pub(super) struct ArtifactSink {
    temporary: Option<PathBuf>,
    relative_path: String,
    partition: Partition,
    writer: Option<ArrowWriter<File>>,
    kind: ArtifactKind,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum ArtifactKind {
    Events,
    Entities,
    Coobservations,
}

impl ArtifactKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Entities => "entities",
            Self::Coobservations => "coobservations",
        }
    }

    fn schema(self) -> irmind_domain::ArtifactSchemaV2 {
        use irmind_domain::ArtifactSchemaV2::{CommonCoobservations, CommonEntities, CommonEvents};
        match self {
            Self::Events => CommonEvents,
            Self::Entities => CommonEntities,
            Self::Coobservations => CommonCoobservations,
        }
    }
}

impl Drop for ArtifactSink {
    fn drop(&mut self) {
        self.writer.take();
        if let Some(path) = self.temporary.take() {
            let _ = fs::remove_file(path);
        }
    }
}

impl ArtifactSink {
    fn new(
        case_dir: &Path,
        hash: &EvidenceHash,
        partition: Partition,
        batch: &RecordBatch,
        kind: ArtifactKind,
    ) -> Result<Self, AppError> {
        let (part, name) = Self::location(&partition, hash, kind)?;
        let dir = case_dir.join(&part);
        fs::create_dir_all(&dir).map_err(storage)?;
        irmind_fs::private_dir(&dir).map_err(storage)?;
        let temporary = dir.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let result = (|| {
            let file = options.open(&temporary).map_err(storage)?;
            irmind_fs::private_file(&temporary).map_err(storage)?;
            let mut properties = WriterProperties::builder()
                .set_compression(Compression::SNAPPY)
                .set_max_row_group_row_count(Some(8192));
            if matches!(kind, ArtifactKind::Entities | ArtifactKind::Coobservations) {
                properties = properties
                    .set_column_bloom_filter_enabled(ColumnPath::from("entity_value"), true)
                    .set_column_bloom_filter_fpp(ColumnPath::from("entity_value"), 0.01);
            }
            let properties = properties.build();
            let writer =
                ArrowWriter::try_new(file, batch.schema(), Some(properties)).map_err(storage)?;
            Ok(Self {
                temporary: Some(temporary.clone()),
                relative_path: format!("{part}/{name}"),
                partition,
                writer: Some(writer),
                kind,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn location(
        partition: &Partition,
        hash: &EvidenceHash,
        kind: ArtifactKind,
    ) -> Result<(String, String), AppError> {
        let prefix = partition
            .scope
            .as_ref()
            .ok_or_else(invalid_source)?
            .path_prefix()
            .map_err(|_| invalid_source())?;
        let route = partition
            .mapping_route
            .as_deref()
            .ok_or_else(invalid_source)?;
        if route.len() != 64
            || !route
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid_source());
        }
        let name = format!(
            "{}.part-{}.{}.direct.common.map-{route}.parquet",
            hash.as_str(),
            partition.segment,
            kind.suffix()
        );
        Ok((prefix.trim_end_matches('/').into(), name))
    }

    fn append(&mut self, batch: &RecordBatch) -> Result<(), AppError> {
        let writer = self.writer.as_mut().ok_or_else(invalid_source)?;
        writer.write(batch).map_err(storage)?;
        if writer.memory_size() >= super::BATCH_BYTES {
            writer.flush().map_err(storage)?;
        }
        Ok(())
    }

    fn finish_cancelable(
        mut self,
        hash: &EvidenceHash,
        parser: irmind_app::ParserIdentity<'_>,
        cancel: &CancellationToken,
    ) -> Result<StagedArtifact, AppError> {
        let writer = self.writer.take().ok_or_else(invalid_source)?;
        let metadata = writer.close().map_err(storage)?;
        let temporary = self.temporary.as_ref().ok_or_else(invalid_source)?;
        // Windows FlushFileBuffers requires a writable handle.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary)
            .map_err(storage)?;
        file.sync_all().map_err(storage)?;
        let (digest, size) = ParquetStore::hash_reader(&mut file, cancel)?;
        let manifest = precise::manifest(&self, hash, parser, size, &digest)?;
        Ok(StagedArtifact {
            rows: Some(u64::try_from(metadata.file_metadata().num_rows()).map_err(storage)?),
            temporary: self.temporary.take().ok_or_else(invalid_source)?,
            manifest,
        })
    }
}

impl Drop for StagedArtifact {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

fn table_batches(rows: &[RecordRow]) -> Result<(RecordBatch, RecordBatch, RecordBatch), AppError> {
    if rows.is_empty() || rows.iter().any(|row| row.common.is_none()) {
        return Err(invalid_source());
    }
    Ok((
        common::events(rows)?,
        common::entities(rows, false)?,
        common::entities(rows, true)?,
    ))
}
