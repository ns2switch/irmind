//! Bounded source snapshot metadata shared by the mapped decoder and writers.
use super::super::{
    AppError, CancellationToken, EvidenceHash, File, Instant, ParquetProfile, ParquetStore,
    StreamingEventParser, invalid_source, storage, storage_phase,
};

pub(in crate::parquet_store) struct VerifiedInput<'a> {
    pub(in crate::parquet_store) decode_budget: irmind_app::source_mapping::DecodeBudget,
    pub(in crate::parquet_store) source: &'a mut File,
    pub(in crate::parquet_store) sample: &'a [u8],
    pub(in crate::parquet_store) relative_path: &'a str,
    pub(in crate::parquet_store) parser: &'a dyn StreamingEventParser,
    pub(in crate::parquet_store) hash: [u8; 32],
    pub(in crate::parquet_store) hash_value: &'a EvidenceHash,
    pub(in crate::parquet_store) size: u64,
    pub(in crate::parquet_store) cancel: &'a CancellationToken,
}

pub(in crate::parquet_store) fn initial_hash(
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
