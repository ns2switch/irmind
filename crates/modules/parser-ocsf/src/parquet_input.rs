use crate::{policy_error, record};
use irmind_app::{AppError, CancellationToken, GraphRecord, ParseReport};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use parquet::file::reader::{FileReader, SerializedFileReader};
use std::io::{Read, Seek, SeekFrom, Write};

const MAX_PARQUET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000_000;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROW_GROUP_BYTES: i64 = 256 * 1024 * 1024;
const MAX_ROW_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn parse(
    source: &str,
    mut reader: impl Read,
    evidence_hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    // The parser port offers Read, while Parquet needs random access to its
    // footer. A private, automatically removed spool bounds memory usage.
    let mut spool =
        tempfile::tempfile().map_err(|_| policy_error("cannot create private OCSF spool"))?;
    let mut total = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|_| policy_error("cannot read OCSF Parquet"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_PARQUET_BYTES {
            return Err(policy_error("OCSF Parquet exceeds 2 GiB per file"));
        }
        spool
            .write_all(&buffer[..count])
            .map_err(|_| policy_error("cannot spool OCSF Parquet"))?;
    }
    spool
        .sync_all()
        .map_err(|_| policy_error("cannot sync OCSF spool"))?;
    validate_footer(&mut spool, total)?;
    let file = SerializedFileReader::new(spool)
        .map_err(|_| policy_error("invalid OCSF Parquet structure"))?;
    validate_row_groups(file.metadata())?;
    let rows = file
        .get_row_iter(None)
        .map_err(|_| policy_error("cannot read OCSF Parquet rows"))?;
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    for (index, row) in rows.enumerate() {
        if index >= MAX_RECORDS {
            return Err(policy_error("OCSF Parquet exceeds record limit"));
        }
        if index.is_multiple_of(256) && cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let row = row.map_err(|_| policy_error("corrupt OCSF Parquet row"))?;
        let value = row.to_json_value();
        let encoded = value.to_string();
        if encoded.len() > MAX_ROW_BYTES {
            reject_row(&mut report, &encoded);
            continue;
        }
        if let Ok(record) = record::parse(index, &value) {
            let location = ParserLocation::new(source, "parser-ocsf", 0)
                .map_err(|_| policy_error("invalid OCSF source path"))?;
            emit(
                Tainted::from_external(
                    record,
                    Provenance::new(evidence_hash, Some(index as u64), SourceKind::File),
                )
                .with_parser_location(location),
            )?;
            report.accepted += 1;
        } else {
            reject_row(&mut report, &encoded);
        }
    }
    Ok(report)
}

fn reject_row(report: &mut ParseReport, encoded: &str) {
    report.rejected += 1;
    if report.samples.len() < 3 {
        report.samples.push(
            encoded
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
}

fn validate_row_groups(
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

fn validate_footer(spool: &mut std::fs::File, size: u64) -> Result<(), AppError> {
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
