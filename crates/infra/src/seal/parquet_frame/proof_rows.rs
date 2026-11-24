//! Read only the provenance columns at the authenticated physical row offsets.
use super::{AppError, FrameReader, storage, storage_reason};
use arrow_array::{Array, RecordBatch, StringArray, UInt64Array};
use irmind_app::{
    CancellationToken,
    v10_proofs::{V10RowReference, verify_v10_row_identity},
};
use irmind_domain::{ArtifactSchemaV2, ParquetArtifact};
use parquet::{
    arrow::{
        ProjectionMask,
        arrow_reader::{
            ArrowReaderBuilder, ParquetRecordBatchReaderBuilder, RowSelection, RowSelector,
            SyncReader,
        },
    },
    file::reader::ChunkReader,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Seek, SeekFrom},
    ops::Range,
};

pub fn verify_v10_artifact_rows(
    file: &mut File,
    offset: u64,
    artifact: &ParquetArtifact,
    references: &[V10RowReference],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    verify_artifact(file, offset, artifact, references, None, cancel)
}

pub(in crate::seal) fn verify_v10_sigma_rows(
    file: &mut File,
    offset: u64,
    artifact: &ParquetArtifact,
    references: &[V10RowReference],
    time: &Range<i64>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    verify_artifact(file, offset, artifact, references, Some(time), cancel)
}

fn verify_artifact(
    file: &mut File,
    offset: u64,
    artifact: &ParquetArtifact,
    references: &[V10RowReference],
    time: Option<&Range<i64>>,
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
    super::super::frames::verify_raw_with_cancel(
        file,
        core.size,
        core.sha256.as_str(),
        Some(cancel),
    )?;
    let reader = FrameReader {
        file: file.try_clone().map_err(storage)?,
        start: offset,
        size: core.size,
    };
    let result = verify_rows(reader, envelope.pipeline().rows(), references, time, cancel);
    file.seek(SeekFrom::Start(end)).map_err(storage)?;
    result
}

fn verify_rows(
    reader: impl ChunkReader + 'static,
    expected_rows: u64,
    references: &[V10RowReference],
    time: Option<&Range<i64>>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if references.is_empty() {
        return Ok(());
    }
    let (builder, row_count) = row_identity_reader(reader, expected_rows, time.is_some())?;
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
        .with_row_selection(RowSelection::from(selected))
        .build()
        .map_err(storage)?;
    let mut expected = references.iter().copied();
    for batch in rows {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let batch = batch.map_err(storage)?;
        let (hashes, records) = row_identity_columns(&batch)?;
        let common = time
            .map(|_| {
                batch
                    .column_by_name("common_payload")
                    .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                    .ok_or_else(invalid)
            })
            .transpose()?;
        for row in 0..batch.num_rows() {
            if let Some((time, common)) = time.zip(common)
                && (common.is_null(row)
                    || !irmind_app::decode_common_event(common.value(row))?
                        .timestamp()
                        .is_some_and(|at| time.contains(&at.instant().unix_micros())))
            {
                return Err(invalid());
            }
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

/// Resolve eligible logical references in physical row order. Authenticate
/// the artifact under the same open handle before decoding any provenance.
pub(in crate::seal) fn locate_v10_artifact_rows(
    mut file: File,
    artifact: &ParquetArtifact,
    wanted: &BTreeMap<String, BTreeSet<u64>>,
    cancel: &CancellationToken,
    mut found: impl FnMut(&str, u64, u64) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let ParquetArtifact::V3(envelope) = artifact;
    if file.metadata().map_err(storage)?.len() != envelope.core().size {
        return Err(invalid());
    }
    verify_v10_artifact_rows(&mut file, 0, artifact, &[], cancel)?;
    let (reader, _) = row_identity_reader(file, envelope.pipeline().rows(), false)?;
    let mut physical_row = 0u64;
    for batch in reader.build().map_err(storage)? {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let batch = batch.map_err(storage)?;
        let (hashes, records) = row_identity_columns(&batch)?;
        for index in 0..batch.num_rows() {
            if hashes.is_null(index) || records.is_null(index) {
                return Err(invalid());
            }
            let source = hashes.value(index);
            let record = records.value(index);
            if wanted
                .get(source)
                .is_some_and(|records| records.contains(&record))
            {
                found(source, record, physical_row)?;
            }
            physical_row = physical_row.checked_add(1).ok_or_else(invalid)?;
        }
    }
    if physical_row != envelope.pipeline().rows() {
        return Err(invalid());
    }
    Ok(())
}

fn row_identity_reader<R: ChunkReader + 'static>(
    reader: R,
    expected_rows: u64,
    with_time: bool,
) -> Result<(ArrowReaderBuilder<SyncReader<R>>, usize), AppError> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(reader).map_err(storage)?;
    let row_count =
        usize::try_from(builder.metadata().file_metadata().num_rows()).map_err(storage)?;
    if row_count as u64 != expected_rows {
        return Err(invalid());
    }
    let schema = builder.schema();
    let source = schema.index_of("source_hash").map_err(storage)?;
    let record = schema.index_of("record_index").map_err(storage)?;
    let mut columns = vec![source, record];
    if with_time {
        columns.push(schema.index_of("common_payload").map_err(storage)?);
    }
    let projection = ProjectionMask::roots(builder.parquet_schema(), columns);
    Ok((
        builder.with_projection(projection).with_batch_size(4096),
        row_count,
    ))
}

fn row_identity_columns(batch: &RecordBatch) -> Result<(&StringArray, &UInt64Array), AppError> {
    let hashes = batch
        .column_by_name("source_hash")
        .and_then(|column| column.as_any().downcast_ref::<StringArray>())
        .ok_or_else(invalid)?;
    let records = batch
        .column_by_name("record_index")
        .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
        .ok_or_else(invalid)?;
    Ok((hashes, records))
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
            verify_rows(
                bytes.clone(),
                3,
                references,
                None,
                &CancellationToken::new(),
            )
        };
        check(&[pointer(0, 0xaa, 1), pointer(2, 0xbb, 1)]).unwrap();
        assert!(check(&[pointer(1, 0xaa, 1)]).is_err());
        assert!(check(&[pointer(2, 0xaa, 1)]).is_err());
        assert!(check(&[pointer(0, 0xaa, 1), pointer(0, 0xaa, 1)]).is_err());
        assert!(check(&[pointer(3, 0xbb, 1)]).is_err());
    }
}
