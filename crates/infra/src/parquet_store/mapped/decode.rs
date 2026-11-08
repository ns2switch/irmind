use super::super::{
    AppError, CaseId, HashingReader, ParquetStore, RecordRow, invalid_source, storage,
};
use crate::parquet_store::local::stream::VerifiedInput;
use irmind_app::source_mapping::{
    DecodedSourceCommitmentV1, MappingCatalog, SourceFileInput, SourceInput, SourceMetadata,
    SourceRecordAccumulator, SourceReferenceV1, decode_source_time_context,
};
use std::io::{Seek, SeekFrom, Write};

impl ParquetStore {
    pub(in crate::parquet_store) fn decode_mapped(
        &self,
        case: &CaseId,
        input: &mut VerifiedInput<'_>,
        emit: &mut dyn FnMut(RecordRow) -> Result<(), AppError>,
    ) -> Result<(irmind_app::ParseReport, DecodedSourceCommitmentV1), AppError> {
        let catalog = self.mapping_catalog.as_deref().ok_or_else(invalid_source)?;
        let logical = input.parser.logical_source(input.relative_path);
        let reference = SourceReferenceV1::file(logical).map_err(|_| invalid_source())?;
        let time = decode_source_time_context(input.parser.timestamp_context())?;
        let metadata = SourceMetadata {
            source: &reference,
            evidence_hash: input.hash,
            time_context: time.as_ref(),
            cancel: input.cancel,
        };
        let id = input.parser.identity_for_source(input.relative_path)?;
        let decoder = catalog
            .decoder(id.name, id.version)
            .map_err(irmind_app::source_mapping::MappingError::into_app)?;
        let mut tuples = self.create_private_object_spool(
            case,
            input
                .size
                .min(10_000_000)
                .checked_mul(49)
                .ok_or_else(invalid_source)?,
        )?;
        let routes = projection_routes(catalog)?;
        let mut acc = SourceRecordAccumulator::new(metadata, id, input.size, catalog)?;
        let mut tuple_writer = std::io::BufWriter::new(tuples.as_file_mut());
        let mut callback = |source| {
            let mapped = acc.accept(&source, &mut tuple_writer)?;
            let mut row = None;
            let route = routes
                .get(&mapped.identity)
                .ok_or_else(invalid_source)?
                .clone();
            mapped.output.inspect(|output| {
                row = Some(RecordRow::from_mapping(
                    output,
                    mapped.output.provenance(),
                    id,
                    input.hash_value,
                    route,
                ));
            });
            emit(row.ok_or_else(invalid_source)??)
        };
        input.source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let report = if decoder.needs_random_access(logical, input.sample) {
            let report = decoder.decode_local_file(
                SourceFileInput {
                    metadata,
                    file: input.source,
                },
                &mut callback,
            )?;
            let (hash, size) = Self::hash_reader(input.source, input.cancel)?;
            check_hash(hash, size, input)?;
            report
        } else {
            let mut reader = HashingReader::new(&mut *input.source);
            let report = decoder.decode_reader(
                SourceInput {
                    metadata,
                    reader: &mut reader,
                },
                &mut callback,
            )?;
            reader.drain(input.cancel)?;
            let size = reader.bytes;
            check_hash(reader.finish(), size, input)?;
            report
        };
        tuple_writer.flush().map_err(storage)?;
        drop(tuple_writer);
        let commitment = acc.finish(tuples.as_file_mut(), &report)?;
        Ok((report, commitment))
    }
}
fn check_hash(hash: [u8; 32], size: u64, input: &VerifiedInput<'_>) -> Result<(), AppError> {
    if hash != input.hash || size != input.size {
        return Err(AppError::EvidenceMismatch(input.hash_value.as_str().into()));
    }
    Ok(())
}
pub(super) fn projection_routes(
    catalog: &MappingCatalog,
) -> Result<std::collections::BTreeMap<Option<irmind_domain::MappingIdentityV1>, String>, AppError>
{
    let snapshots = catalog
        .snapshots()
        .map_err(irmind_app::source_mapping::MappingError::into_app)?;
    let references = snapshots
        .iter()
        .map(irmind_domain::MappingSnapshotV1::reference)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_source())?;
    let catalog_id =
        irmind_domain::mapping_catalog_commitment(&references).map_err(|_| invalid_source())?;
    Ok(std::iter::once(None)
        .chain(snapshots.iter().map(|s| Some(s.mapping().clone())))
        .map(|mapping| {
            let route = route_token(&catalog_id, mapping.as_ref());
            (mapping, route)
        })
        .collect())
}
fn route_token(
    catalog: &irmind_domain::EvidenceHash,
    mapping: Option<&irmind_domain::MappingIdentityV1>,
) -> String {
    let mut bytes = b"irmind-mapped-route-v1\0".to_vec();
    bytes.extend_from_slice(catalog.as_str().as_bytes());
    bytes.push(u8::from(mapping.is_some()));
    if let Some(identity) = mapping {
        for field in [
            identity.id(),
            identity.version(),
            identity.target(),
            identity.implementation().as_str(),
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
    }
    irmind_app::hex(&irmind_app::sha256(&bytes))
}
