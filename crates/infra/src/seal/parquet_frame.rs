//! Validate a hash-authenticated Parquet frame without extracting its contents.
use super::{AppError, storage, storage_reason};
use bytes::Bytes;
use irmind_domain::ArtifactSchemaV2;
use parquet::{
    arrow::arrow_reader::ParquetRecordBatchReaderBuilder,
    errors::{ParquetError, Result as ParquetResult},
    file::reader::{ChunkReader, Length},
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Take},
};

pub(super) fn verify_common(
    input: &mut File,
    size: u64,
    expected: &str,
    schema: ArtifactSchemaV2,
    rows: Option<u64>,
) -> Result<(), AppError> {
    let start = input.stream_position().map_err(storage)?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| storage_reason("invalid derived-file length"))?;
    super::frames::verify_raw(input, size, expected)?;
    let source = FrameReader {
        file: input.try_clone().map_err(storage)?,
        start,
        size,
    };
    let validated = ParquetRecordBatchReaderBuilder::try_new(source)
        .map_err(storage)
        .and_then(|reader| {
            crate::parquet_store::validate_common_export_schema(schema, reader.schema())?;
            if rows.is_some_and(|expected| {
                u64::try_from(reader.metadata().file_metadata().num_rows()).ok() != Some(expected)
            }) {
                return Err(storage_reason(
                    "derived-file row count differs from signed envelope",
                ));
            }
            Ok(())
        });
    // File clones share a cursor. Metadata reads must not consume another frame.
    input.seek(SeekFrom::Start(end)).map_err(storage)?;
    validated
}

struct FrameReader {
    file: File,
    start: u64,
    size: u64,
}
impl FrameReader {
    fn at(&self, offset: u64, length: u64) -> ParquetResult<File> {
        if offset.checked_add(length).is_none_or(|end| end > self.size) {
            return Err(ParquetError::General(
                "Parquet frame range is invalid".into(),
            ));
        }
        let absolute = self
            .start
            .checked_add(offset)
            .ok_or_else(|| ParquetError::General("Parquet frame offset is invalid".into()))?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(absolute))?;
        Ok(file)
    }
}
impl Length for FrameReader {
    fn len(&self) -> u64 {
        self.size
    }
}
impl ChunkReader for FrameReader {
    type T = Take<File>;

    fn get_read(&self, start: u64) -> ParquetResult<Self::T> {
        let left = self
            .size
            .checked_sub(start)
            .ok_or_else(|| ParquetError::General("Parquet frame offset is invalid".into()))?;
        Ok(self.at(start, left)?.take(left))
    }

    fn get_bytes(&self, start: u64, length: usize) -> ParquetResult<Bytes> {
        let mut file = self.at(start, length as u64)?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        Ok(bytes.into())
    }
}

#[cfg(test)]
mod tests;
