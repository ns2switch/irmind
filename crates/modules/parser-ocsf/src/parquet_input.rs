use crate::policy_error;
use irmind_app::AppError;
use std::io::{Read, Seek, SeekFrom};

pub(super) const MAX_PARQUET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROW_GROUP_BYTES: i64 = 256 * 1024 * 1024;

pub(super) fn validate_row_groups(
    metadata: &parquet::file::metadata::ParquetMetaData,
) -> Result<(), AppError> {
    if metadata.num_row_groups() > 100_000
        || metadata.file_metadata().schema_descr().num_columns() > 128
    {
        return Err(policy_error("OCSF Parquet has too many groups or columns"));
    }
    for group in metadata.row_groups() {
        if group.total_byte_size() > MAX_ROW_GROUP_BYTES
            || group.num_rows() > 1_000_000
            || group.columns().iter().any(|column| {
                column.uncompressed_size() > MAX_ROW_GROUP_BYTES
                    || column.compressed_size() > MAX_ROW_GROUP_BYTES
            })
        {
            return Err(policy_error("OCSF Parquet row group exceeds size limit"));
        }
    }
    Ok(())
}

pub(super) fn validate_footer(spool: &mut std::fs::File, size: u64) -> Result<(), AppError> {
    if size < 12 {
        return Err(policy_error("OCSF Parquet footer is missing"));
    }
    spool
        .seek(SeekFrom::End(-8))
        .map_err(|_| policy_error("cannot inspect OCSF Parquet footer"))?;
    let mut footer = [0u8; 8];
    spool
        .read_exact(&mut footer)
        .map_err(|_| policy_error("cannot inspect OCSF Parquet footer"))?;
    let metadata_size = u64::from(u32::from_le_bytes([
        footer[0], footer[1], footer[2], footer[3],
    ]));
    if &footer[4..] != b"PAR1"
        || metadata_size > MAX_METADATA_BYTES
        || metadata_size.saturating_add(12) > size
    {
        return Err(policy_error(
            "OCSF Parquet metadata is invalid or too large",
        ));
    }
    Ok(())
}
