use super::{
    AppError, ArrayRef, ArrowWriter, BTreeMap, CancellationToken, Compression, EvidenceHash, File,
    GraphRecord, OpenOptions, ParquetArtifact, ParquetStore, Path, PathBuf, RecordBatch,
    StringArray, UInt64Array, WriterProperties, fs, invalid_source, storage,
};
use irmind_domain::ParquetArtifactV1;
use std::sync::Arc;

mod batch;
pub(super) mod precise;
mod staged_time;
use batch::{coobservation_batch, entity_batch, record_batch};
use parquet::schema::types::ColumnPath;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
pub(super) struct Partition {
    date: String,
    account: String,
    region: String,
    #[serde(skip)]
    scope: Option<irmind_domain::ArtifactPartitionV2>,
    segment: u32,
}

impl Partition {
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
    pub temporary: PathBuf,
    pub manifest: ParquetArtifact,
}

pub(super) struct ArtifactSink {
    temporary: Option<PathBuf>,
    relative_path: String,
    partition: Partition,
    writer: Option<ArrowWriter<File>>,
    kind: ArtifactKind,
    precise: bool,
}

#[derive(Clone, Copy)]
enum ArtifactKind {
    Events,
    Entities,
    LegacyEntities,
    Coobservations,
}

impl ArtifactKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Entities | Self::LegacyEntities => "entities",
            Self::Coobservations => "coobservations",
        }
    }

    fn schema(self) -> &'static str {
        match self {
            Self::Events => "irmind-events-v2",
            Self::Entities => "irmind-entities-v2",
            Self::LegacyEntities => "irmind-entities-v1",
            Self::Coobservations => "irmind-coobservations-v1",
        }
    }
}

pub(super) struct PartitionSinks {
    events: ArtifactSink,
    entities: ArtifactSink,
    coobservations: Option<ArtifactSink>,
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
        let precise = matches!(
            batch
                .schema()
                .field_with_name("event_time")
                .map(arrow::datatypes::Field::data_type),
            Ok(arrow::datatypes::DataType::Timestamp(_, _))
        );
        let (part, name) = Self::location(&partition, hash, kind, precise)?;
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
                .set_max_row_group_row_count(Some(
                    if matches!(kind, ArtifactKind::Events | ArtifactKind::LegacyEntities) {
                        8192
                    } else {
                        1024
                    },
                ));
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
                precise,
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
        precise: bool,
    ) -> Result<(String, String), AppError> {
        let part = if let Some(scope) = &partition.scope {
            scope
                .path_prefix()
                .map_err(|_| invalid_source())?
                .trim_end_matches('/')
                .to_owned()
        } else if precise {
            format!("date={}", partition.date)
        } else {
            format!(
                "date={}/account={}/region={}",
                partition.date, partition.account, partition.region
            )
        };
        let name = if partition.scope.is_some() {
            format!(
                "{}.part-{}.{}.parquet",
                hash.as_str(),
                partition.segment,
                kind.suffix()
            )
        } else if precise {
            let key = format!("{}\0{}", partition.account, partition.region);
            format!(
                "{}.{}.{}.parquet",
                hash.as_str(),
                irmind_app::hex(&irmind_app::sha256(key.as_bytes())),
                kind.suffix()
            )
        } else {
            format!("{}.{}.parquet", hash.as_str(), kind.suffix())
        };
        Ok((part, name))
    }

    fn append(&mut self, batch: &RecordBatch) -> Result<(), AppError> {
        let writer = self.writer.as_mut().ok_or_else(invalid_source)?;
        writer.write(batch).map_err(storage)?;
        if matches!(
            self.kind,
            ArtifactKind::Entities | ArtifactKind::Coobservations
        ) {
            writer.flush().map_err(storage)?;
        }
        Ok(())
    }

    fn finish(
        mut self,
        hash: &EvidenceHash,
        parser: irmind_app::ParserIdentity<'_>,
    ) -> Result<StagedArtifact, AppError> {
        let writer = self.writer.take().ok_or_else(invalid_source)?;
        writer.close().map_err(storage)?;
        let temporary = self.temporary.as_ref().ok_or_else(invalid_source)?;
        // Windows FlushFileBuffers requires a writable handle.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary)
            .map_err(storage)?;
        file.sync_all().map_err(storage)?;
        let (digest, size) = ParquetStore::hash_reader(&mut file, &CancellationToken::new())?;
        Ok(StagedArtifact {
            temporary: self.temporary.take().ok_or_else(invalid_source)?,
            manifest: if self.precise {
                precise::manifest(&self, hash, parser, size, &digest)?
            } else {
                ParquetArtifactV1 {
                    path: self.relative_path.clone(),
                    size,
                    sha256: EvidenceHash::parse(&irmind_app::hex(&digest))
                        .map_err(|_| invalid_source())?,
                    parser_version: parser.version.into(),
                    schema_version: self.kind.schema().into(),
                    partition_date: self.partition.date.clone(),
                    partition_account: self.partition.account.clone(),
                    partition_region: self.partition.region.clone(),
                    source_hashes: vec![hash.clone()],
                }
                .into()
            },
        })
    }
}

impl Drop for StagedArtifact {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

pub(super) fn batch_to_parquet(
    case_dir: &Path,
    hash: &EvidenceHash,
    grouped: &mut BTreeMap<Partition, Vec<RecordRow>>,
    open: &mut BTreeMap<Partition, PartitionSinks>,
    legacy_entities: bool,
) -> Result<(), AppError> {
    for (partition, rows) in std::mem::take(grouped) {
        if rows.is_empty() {
            continue;
        }
        let mut events = record_batch(&rows)?;
        let mut entities = entity_batch(&rows, !legacy_entities)?;
        let mut coobservations = (!legacy_entities)
            .then(|| coobservation_batch(&rows))
            .transpose()?;
        if rows[0].precise {
            events = precise::columns(&events, &rows, &(0..rows.len()).collect::<Vec<_>>())?;
            let pairs = batch::pairs(&rows, true)
                .into_iter()
                .map(|(row, _)| row)
                .collect::<Vec<_>>();
            entities = precise::columns(&entities, &rows, &pairs)?;
            coobservations = coobservations
                .map(|batch| precise::columns(&batch, &rows, &pairs))
                .transpose()?;
        }
        if !open.contains_key(&partition) {
            if open.len() >= 64 {
                return Err(AppError::Policy(
                    "source spans too many Parquet partitions".into(),
                ));
            }
            open.insert(
                partition.clone(),
                PartitionSinks {
                    events: ArtifactSink::new(
                        case_dir,
                        hash,
                        partition.clone(),
                        &events,
                        ArtifactKind::Events,
                    )?,
                    entities: ArtifactSink::new(
                        case_dir,
                        hash,
                        partition.clone(),
                        &entities,
                        if legacy_entities {
                            ArtifactKind::LegacyEntities
                        } else {
                            ArtifactKind::Entities
                        },
                    )?,
                    coobservations: coobservations
                        .as_ref()
                        .map(|batch| {
                            ArtifactSink::new(
                                case_dir,
                                hash,
                                partition.clone(),
                                batch,
                                ArtifactKind::Coobservations,
                            )
                        })
                        .transpose()?,
                },
            );
        }
        let sinks = open.get_mut(&partition).ok_or_else(invalid_source)?;
        sinks.events.append(&events)?;
        sinks.entities.append(&entities)?;
        if let (Some(sink), Some(batch)) = (&mut sinks.coobservations, &coobservations) {
            sink.append(batch)?;
        }
    }
    Ok(())
}

pub(super) fn finish_parquet(
    open: BTreeMap<Partition, PartitionSinks>,
    hash: &EvidenceHash,
    parser: irmind_app::ParserIdentity<'_>,
) -> Result<Vec<StagedArtifact>, AppError> {
    let mut artifacts = Vec::new();
    for sinks in open.into_values() {
        artifacts.push(sinks.events.finish(hash, parser)?);
        artifacts.push(sinks.entities.finish(hash, parser)?);
        if let Some(coobservations) = sinks.coobservations {
            artifacts.push(coobservations.finish(hash, parser)?);
        }
    }
    Ok(artifacts)
}
