//! Read only the provenance columns at the authenticated physical row offsets.
use super::{AppError, FrameReader, storage, storage_reason};
use arrow_array::{Array, StringArray, UInt64Array};
use irmind_app::{
    CancellationToken,
    v10_proofs::{V10RowReference, verify_v10_row_identity},
};
use irmind_domain::{ArtifactSchemaV2, ParquetArtifact};
use parquet::{
    arrow::{
        ProjectionMask,
        arrow_reader::{ParquetRecordBatchReaderBuilder, RowSelection, RowSelector},
    },
    file::reader::ChunkReader,
};
use std::{
    fs::File,
    io::{Seek, SeekFrom},
};

pub fn verify_v10_artifact_rows(
    file: &mut File,
    offset: u64,
    artifact: &ParquetArtifact,
    references: &[V10RowReference],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let ParquetArtifact::V3(envelope) = artifact;
    let core = envelope.core();
    if core.schema != ArtifactSchemaV2::CommonEvents
        || references.iter().any(|reference| {
            irmind_domain::EvidenceHash::from_bytes(reference.artifact.artifact_sha256)
                != core.sha256
        })
    {
        return Err(invalid());
    }
    let end = offset.checked_add(core.size).ok_or_else(invalid)?;
    if end > file.metadata().map_err(storage)?.len() {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(offset)).map_err(storage)?;
    super::super::frames::verify_raw(file, core.size, core.sha256.as_str())?;
    let reader = FrameReader {
        file: file.try_clone().map_err(storage)?,
        start: offset,
        size: core.size,
    };
    let result = verify_rows(reader, envelope.pipeline().rows(), references, cancel);
    file.seek(SeekFrom::Start(end)).map_err(storage)?;
    result
}

fn verify_rows(
    reader: impl ChunkReader + 'static,
    expected_rows: u64,
    references: &[V10RowReference],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if references.is_empty() {
        return Ok(());
    }
    let builder = ParquetRecordBatchReaderBuilder::try_new(reader).map_err(storage)?;
    let row_count =
        usize::try_from(builder.metadata().file_metadata().num_rows()).map_err(storage)?;
    if row_count as u64 != expected_rows {
        return Err(invalid());
    }
    let schema = builder.schema();
    let source_column = schema.index_of("source_hash").map_err(storage)?;
    let record_column = schema.index_of("record_index").map_err(storage)?;
    let projection =
        ProjectionMask::roots(builder.parquet_schema(), [source_column, record_column]);
    let mut selected = Vec::new();
    let mut next = 0usize;
    for reference in references {
        let index = usize::try_from(reference.physical_row).map_err(storage)?;
        if index < next || index >= row_count {
            return Err(invalid());
        }
        if index > next {
            selected.push(RowSelector::skip(index - next));
        }
        selected.push(RowSelector::select(1));
        next = index + 1;
    }
    if next < row_count {
        selected.push(RowSelector::skip(row_count - next));
    }
    let rows = builder
        .with_projection(projection)
        .with_row_selection(RowSelection::from(selected))
        .with_batch_size(4096)
        .build()
        .map_err(storage)?;
    let mut expected = references.iter().copied();
    for batch in rows {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let batch = batch.map_err(storage)?;
        let hashes = batch
            .column_by_name("source_hash")
            .and_then(|column| column.as_any().downcast_ref::<StringArray>())
            .ok_or_else(invalid)?;
        let records = batch
            .column_by_name("record_index")
            .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
            .ok_or_else(invalid)?;
        for row in 0..batch.num_rows() {
            if hashes.is_null(row) || records.is_null(row) {
                return Err(invalid());
            }
            verify_v10_row_identity(
                expected.next().ok_or_else(invalid)?,
                hashes.value(row),
                records.value(row),
            )?;
        }
    }
    if expected.next().is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> AppError {
    storage_reason("proof row does not match the authenticated Parquet artifact")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use arrow_array::RecordBatch;
    use irmind_app::v10_proofs::{V10ArtifactReference, V10AuditReference, V10SourceReference};
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;

    #[test]
    fn exact_physical_proof_rows_resolve_without_materializing_other_columns() {
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let batch = RecordBatch::try_from_iter([
            (
                "source_hash",
                Arc::new(StringArray::from(vec![
                    first.as_str(),
                    first.as_str(),
                    second.as_str(),
                ])) as _,
            ),
            (
                "record_index",
                Arc::new(UInt64Array::from(vec![1, 2, 1])) as _,
            ),
            (
                "unused",
                Arc::new(StringArray::from(vec!["x", "y", "z"])) as _,
            ),
        ])
        .unwrap();
        let mut output = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut output, batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let entry = V10AuditReference {
            sequence: 3,
            entry_sha256: [3; 32],
        };
        let artifact = V10ArtifactReference {
            entry,
            artifact_sha256: [4; 32],
        };
        let pointer = |physical_row, evidence, record| V10RowReference {
            physical_row,
            source: V10SourceReference {
                manifest: entry,
                evidence_sha256: [evidence; 32],
            },
            record,
            artifact,
        };
        let bytes = bytes::Bytes::from(output);
        let check = |references: &[V10RowReference]| {
            verify_rows(bytes.clone(), 3, references, &CancellationToken::new())
        };
        check(&[pointer(0, 0xaa, 1), pointer(2, 0xbb, 1)]).unwrap();
        assert!(check(&[pointer(1, 0xaa, 1)]).is_err());
        assert!(check(&[pointer(2, 0xaa, 1)]).is_err());
        assert!(check(&[pointer(0, 0xaa, 1), pointer(0, 0xaa, 1)]).is_err());
        assert!(check(&[pointer(3, 0xbb, 1)]).is_err());
    }
}
