use super::{
    AppError, ArrayRef, ArrowWriter, BTreeMap, CancellationToken, Compression, EvidenceHash, File,
    GraphRecord, OpenOptions, ParquetArtifactV1, ParquetStore, Path, PathBuf, RecordBatch,
    StringArray, UInt64Array, WriterProperties, fs, invalid_source, storage,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use std::sync::Arc;

mod batch;
use batch::{coobservation_batch, entity_batch, record_batch};
use parquet::schema::types::ColumnPath;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Partition {
    date: String,
    account: String,
    region: String,
}

pub(super) struct RecordRow {
    pub partition: Partition,
    hash: String,
    index: u64,
    at: String,
    event: String,
    text: String,
    entities: String,
    entity_pairs: Vec<(String, String)>,
    relations: String,
}

impl RecordRow {
    pub(super) fn from_record(record: &GraphRecord, hash: &EvidenceHash) -> Result<Self, AppError> {
        let value: Value = serde_json::from_str(&record.text).map_err(storage)?;
        let at = if record.at.is_empty() {
            String::new()
        } else {
            DateTime::parse_from_rfc3339(&record.at)
                .map_err(|_| invalid_source())?
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        };
        let account = first_string(
            &value,
            &[
                "/account_id",
                "/recipientAccountId",
                "/userIdentity/accountId",
                "/resource/labels/project_id",
                "/protoPayload/resourceName",
                "/subscriptionId",
            ],
        );
        let region = first_string(
            &value,
            &[
                "/provider",
                "/awsRegion",
                "/resource/labels/location",
                "/region",
                "/location",
            ],
        );
        let region = if region.is_empty()
            && value.get("event_id").is_some()
            && value
                .get("principal")
                .and_then(Value::as_str)
                .is_some_and(|principal| principal.starts_with("arn:aws:"))
        {
            "aws"
        } else {
            region
        };
        let relations = record
            .relations
            .iter()
            .map(|relation| {
                [
                    relation.from_kind.as_str(),
                    relation.from_value.as_str(),
                    relation.relation.as_str(),
                    relation.to_kind.as_str(),
                    relation.to_value.as_str(),
                ]
            })
            .collect::<Vec<_>>();
        Ok(Self {
            partition: Partition {
                date: if at.is_empty() {
                    "unknown".into()
                } else {
                    at[..10].into()
                },
                account: safe_partition(account),
                region: safe_partition(region),
            },
            hash: hash.as_str().into(),
            index: u64::try_from(record.index).map_err(storage)?,
            at,
            event: record.event.clone(),
            text: record.text.clone(),
            entities: serde_json::to_string(&record.entities).map_err(storage)?,
            entity_pairs: record.entities.clone(),
            relations: serde_json::to_string(&relations).map_err(storage)?,
        })
    }

    pub(super) fn estimated_bytes(&self) -> usize {
        self.text.len()
            + self.entities.len()
            + self.relations.len()
            + self.event.len()
            + self.at.len()
            + self.hash.len()
            + self.entities.len().saturating_mul(self.entity_pairs.len())
            + self
                .entity_pairs
                .iter()
                .map(|(kind, value)| kind.len() + value.len())
                .sum::<usize>()
    }
}

fn first_string<'a>(value: &'a Value, pointers: &[&str]) -> &'a str {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
        .unwrap_or("")
}

pub(super) fn safe_partition(value: &str) -> String {
    if value.is_empty() {
        return "unknown".into();
    }
    if value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return value.to_ascii_lowercase();
    }
    format!(
        "h{}",
        &irmind_app::hex(&irmind_app::sha256(value.as_bytes()))[..16]
    )
}

pub(super) struct StagedArtifact {
    pub temporary: PathBuf,
    pub manifest: ParquetArtifactV1,
}

pub(super) struct ArtifactSink {
    temporary: Option<PathBuf>,
    relative_path: String,
    partition: Partition,
    writer: Option<ArrowWriter<File>>,
    kind: ArtifactKind,
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
        let part = format!(
            "date={}/account={}/region={}",
            partition.date, partition.account, partition.region
        );
        let dir = case_dir.join(&part);
        fs::create_dir_all(&dir).map_err(storage)?;
        irmind_fs::private_dir(&dir).map_err(storage)?;
        let name = format!("{}.{}.parquet", hash.as_str(), kind.suffix());
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
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
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
        parser_version: &str,
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
            manifest: ParquetArtifactV1 {
                path: self.relative_path.clone(),
                size,
                sha256: EvidenceHash::parse(&irmind_app::hex(&digest))
                    .map_err(|_| invalid_source())?,
                parser_version: parser_version.into(),
                schema_version: self.kind.schema().into(),
                partition_date: self.partition.date.clone(),
                partition_account: self.partition.account.clone(),
                partition_region: self.partition.region.clone(),
                source_hashes: vec![hash.clone()],
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
        let events = record_batch(&rows)?;
        let entities = entity_batch(&rows, !legacy_entities)?;
        let coobservations = (!legacy_entities)
            .then(|| coobservation_batch(&rows))
            .transpose()?;
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
    parser_version: &str,
) -> Result<Vec<StagedArtifact>, AppError> {
    let mut artifacts = Vec::new();
    for sinks in open.into_values() {
        artifacts.push(sinks.events.finish(hash, parser_version)?);
        artifacts.push(sinks.entities.finish(hash, parser_version)?);
        if let Some(coobservations) = sinks.coobservations {
            artifacts.push(coobservations.finish(hash, parser_version)?);
        }
    }
    Ok(artifacts)
}
