use super::{
    AppError, BATCH_BYTES, BATCH_ROWS, BTreeMap, CancellationToken, EvidenceHash, File,
    GraphRecord, HashingReader, Instant, ParquetProfile, ParquetStore, ParseReport, Partition,
    PartitionSinks, Path, RecordRow, Seek, SeekFrom, StreamingEventParser, batch_to_parquet,
    invalid_source, storage, storage_phase,
};

pub(super) struct StreamInput<'a> {
    pub(super) source: &'a mut File,
    pub(super) sample: &'a [u8],
    pub(super) relative_path: &'a str,
    pub(super) hash: [u8; 32],
    pub(super) hash_value: &'a EvidenceHash,
    pub(super) size: u64,
    pub(super) case_dir: &'a Path,
    pub(super) parser: &'a dyn StreamingEventParser,
    pub(super) cancel: &'a CancellationToken,
    pub(super) profile: Option<&'a ParquetProfile>,
    pub(super) legacy_entities: bool,
}

pub(super) fn stream_records(
    input: StreamInput<'_>,
) -> Result<(ParseReport, BTreeMap<Partition, PartitionSinks>), AppError> {
    let StreamInput {
        source,
        sample,
        relative_path,
        hash,
        hash_value,
        size,
        case_dir,
        parser,
        cancel,
        profile,
        legacy_entities,
    } = input;
    let mut open: BTreeMap<Partition, PartitionSinks> = BTreeMap::new();
    let mut grouped: BTreeMap<Partition, Vec<RecordRow>> = BTreeMap::new();
    let mut buffered = 0usize;
    let mut emit = |tainted: irmind_domain::Tainted<GraphRecord>| {
        let row_started = Instant::now();
        let mut row = None;
        tainted.inspect(|record| row = Some(RecordRow::from_record(record, hash_value)));
        let row = row.ok_or_else(invalid_source)??;
        if let Some(profile) = profile {
            profile.record_row(row_started.elapsed());
        }
        buffered = buffered.saturating_add(row.estimated_bytes());
        grouped.entry(row.partition.clone()).or_default().push(row);
        if buffered >= BATCH_BYTES || grouped.values().map(Vec::len).sum::<usize>() >= BATCH_ROWS {
            flush_batch(
                case_dir,
                hash_value,
                &mut grouped,
                &mut open,
                legacy_entities,
                profile,
            )?;
            buffered = 0;
        }
        Ok(())
    };
    let report = parse_and_verify(
        VerifiedInput {
            source,
            sample,
            relative_path,
            parser,
            hash,
            hash_value,
            size,
            cancel,
        },
        &mut emit,
    )?;
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    flush_batch(
        case_dir,
        hash_value,
        &mut grouped,
        &mut open,
        legacy_entities,
        profile,
    )?;
    if report.accepted == 0 {
        return Err(invalid_source());
    }
    Ok((report, open))
}

struct VerifiedInput<'a> {
    source: &'a mut File,
    sample: &'a [u8],
    relative_path: &'a str,
    parser: &'a dyn StreamingEventParser,
    hash: [u8; 32],
    hash_value: &'a EvidenceHash,
    size: u64,
    cancel: &'a CancellationToken,
}

fn parse_and_verify(
    input: VerifiedInput<'_>,
    emit: &mut dyn FnMut(irmind_domain::Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let VerifiedInput {
        source,
        sample,
        relative_path,
        parser,
        hash,
        hash_value,
        size,
        cancel,
    } = input;
    source.seek(SeekFrom::Start(0)).map_err(storage)?;
    if parser.prefers_local_file(relative_path, sample) {
        let report = parser
            .parse_local_file_report(relative_path, source, hash, cancel, emit)
            .map_err(|error| {
                storage_phase(
                    error,
                    irmind_app::AdapterStorageError::CannotParseParquetSource,
                )
            })?;
        source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let (observed_hash, observed_size) = ParquetStore::hash_reader(source, cancel)?;
        if observed_size != size || observed_hash != hash {
            return Err(AppError::EvidenceMismatch(hash_value.as_str().into()));
        }
        return Ok(report);
    }
    let mut second_pass = HashingReader::new(source);
    let report = parser
        .parse_reader_report(relative_path, &mut second_pass, hash, cancel, emit)
        .map_err(|error| {
            storage_phase(
                error,
                irmind_app::AdapterStorageError::CannotParseParquetSource,
            )
        })?;
    second_pass.drain(cancel).map_err(|error| {
        storage_phase(
            error,
            irmind_app::AdapterStorageError::CannotOpenParquetSource,
        )
    })?;
    if second_pass.bytes != size || second_pass.finish() != hash {
        return Err(AppError::EvidenceMismatch(hash_value.as_str().into()));
    }
    Ok(report)
}

fn flush_batch(
    case_dir: &Path,
    hash_value: &EvidenceHash,
    grouped: &mut BTreeMap<Partition, Vec<RecordRow>>,
    open: &mut BTreeMap<Partition, PartitionSinks>,
    legacy_entities: bool,
    profile: Option<&ParquetProfile>,
) -> Result<(), AppError> {
    let parquet_started = Instant::now();
    batch_to_parquet(case_dir, hash_value, grouped, open, legacy_entities).map_err(|error| {
        storage_phase(
            error,
            irmind_app::AdapterStorageError::CannotPrepareParquetOutput,
        )
    })?;
    if let Some(profile) = profile {
        profile.record_parquet(parquet_started.elapsed());
    }
    Ok(())
}

pub(super) fn initial_hash(
    source: &mut File,
    cancel: &CancellationToken,
    profile: Option<&ParquetProfile>,
) -> Result<(std::fs::Metadata, [u8; 32], u64), AppError> {
    let metadata = source.metadata().map_err(|error| {
        storage_phase(
            storage(error),
            irmind_app::AdapterStorageError::CannotOpenParquetSource,
        )
    })?;
    let started = Instant::now();
    let (hash, size) = ParquetStore::hash_reader(source, cancel).map_err(|error| {
        storage_phase(
            error,
            irmind_app::AdapterStorageError::CannotOpenParquetSource,
        )
    })?;
    if let Some(profile) = profile {
        profile.record_hash(started.elapsed());
    }
    if size != metadata.len() {
        return Err(invalid_source());
    }
    Ok((metadata, hash, size))
}
