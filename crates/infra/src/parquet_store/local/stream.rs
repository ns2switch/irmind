use super::{
    AppError, BATCH_BYTES, BATCH_ROWS, BTreeMap, CancellationToken, EvidenceHash, File,
    GraphRecord, HashingReader, Instant, ParquetProfile, ParquetStore, Partition, PartitionSinks,
    Path, RecordRow, Seek, SeekFrom, StreamingEventParser, batch_to_parquet, invalid_source,
    storage, storage_phase,
};

pub(super) struct StreamInput<'a> {
    pub(super) source: &'a mut File,
    pub(super) relative_path: &'a str,
    pub(super) hash: [u8; 32],
    pub(super) hash_value: &'a EvidenceHash,
    pub(super) size: u64,
    pub(super) case_dir: &'a Path,
    pub(super) parser: &'a dyn StreamingEventParser,
    pub(super) cancel: &'a CancellationToken,
    pub(super) profile: Option<&'a ParquetProfile>,
}

pub(super) fn stream_records(
    input: StreamInput<'_>,
) -> Result<(usize, BTreeMap<Partition, PartitionSinks>), AppError> {
    let StreamInput {
        source,
        relative_path,
        hash,
        hash_value,
        size,
        case_dir,
        parser,
        cancel,
        profile,
    } = input;
    source.seek(SeekFrom::Start(0)).map_err(|error| {
        storage_phase(
            storage(error),
            irmind_app::AdapterStorageError::CannotOpenParquetSource,
        )
    })?;
    let mut second_pass = HashingReader::new(source);
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
            let parquet_started = Instant::now();
            batch_to_parquet(case_dir, hash_value, &mut grouped, &mut open).map_err(|error| {
                storage_phase(
                    error,
                    irmind_app::AdapterStorageError::CannotPrepareParquetOutput,
                )
            })?;
            if let Some(profile) = profile {
                profile.record_parquet(parquet_started.elapsed());
            }
            buffered = 0;
        }
        Ok(())
    };
    let records = parser
        .parse_reader(relative_path, &mut second_pass, hash, cancel, &mut emit)
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
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let parquet_started = Instant::now();
    batch_to_parquet(case_dir, hash_value, &mut grouped, &mut open).map_err(|error| {
        storage_phase(
            error,
            irmind_app::AdapterStorageError::CannotPrepareParquetOutput,
        )
    })?;
    if let Some(profile) = profile {
        profile.record_parquet(parquet_started.elapsed());
    }
    if records == 0 {
        return Err(invalid_source());
    }
    Ok((records, open))
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
