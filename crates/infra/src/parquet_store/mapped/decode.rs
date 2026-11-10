use super::super::{
    AppError, CaseId, HashingReader, ParquetStore, RecordRow, invalid_source, storage,
};
use crate::parquet_store::local::stream::VerifiedInput;
use irmind_app::source_mapping::{
    DecodeInput, DecodedSourceCommitmentV1, MappingCatalog, SourceFileInput, SourceInput,
    SourceMetadata, SourceRecordAccumulator, SourceReferenceV1, decode_source_time_context,
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
        let parser = input.parser;
        let logical = parser.logical_source(input.relative_path);
        let hash_value = input.hash_value;
        let reference = SourceReferenceV1::file(logical).map_err(|_| invalid_source())?;
        let time = decode_source_time_context(input.parser.timestamp_context())?;
        let metadata = SourceMetadata {
            source: &reference,
            evidence_hash: input.hash,
            time_context: time.as_ref(),
            cancel: input.cancel,
        };
        let id = parser.identity_for_source(input.relative_path)?;
        let decoder = catalog
            .decoder(id.name, id.version)
            .map_err(irmind_app::source_mapping::MappingError::into_app)?;
        let mut tuple_disk =
            crate::parquet_store::partitioning::temporary::DiskLease::new(self.profile.clone());
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
            let mapped = {
                let _timer = self
                    .profile
                    .as_ref()
                    .map(|p| p.mapping_timer(super::super::profile::MappingPhase::ValidateAndMap));
                acc.accept(&source, &mut tuple_writer)?
            };
            // SourceRecordSetV1 commits fixed 49-byte tuples; this includes
            // buffered bytes as well as tuples already flushed to the spool.
            tuple_disk.add(49)?;
            let timer = self
                .profile
                .as_ref()
                .map(|p| p.mapping_timer(super::super::profile::MappingPhase::Project));
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
                    hash_value,
                    route,
                ));
            });
            let row = row.ok_or_else(invalid_source)??;
            drop(timer);
            emit(row)
        };
        let report = decode_source(input, decoder, metadata, &mut callback)?;
        tuple_writer.flush().map_err(storage)?;
        drop(tuple_writer);
        let _timer = self
            .profile
            .as_ref()
            .map(|p| p.mapping_timer(super::super::profile::MappingPhase::InputCommit));
        let commitment = acc.finish(tuples.as_file_mut(), &report)?;
        Ok((report, commitment))
    }
}
fn decode_source(
    input: &mut VerifiedInput<'_>,
    decoder: &dyn irmind_app::SourceDecoder,
    metadata: SourceMetadata<'_>,
    emit: &mut dyn FnMut(
        irmind_domain::Tainted<irmind_domain::SourceRecordV1>,
    ) -> Result<(), AppError>,
) -> Result<irmind_app::ParseReport, AppError> {
    let logical = metadata.source.reference();
    input.source.seek(SeekFrom::Start(0)).map_err(storage)?;
    let report = if decoder.needs_random_access(logical, input.sample) {
        let mut callback_failed = false;
        let result = decoder.decode_with_budget(
            DecodeInput::File(SourceFileInput {
                metadata,
                file: input.source,
            }),
            input.decode_budget,
            &mut |record| {
                let result = emit(record);
                callback_failed |= result.is_err();
                result
            },
        );
        let report = source_result(
            input.relative_path,
            input.sample,
            input.cancel.is_cancelled(),
            result,
            callback_failed,
        )?;
        let (hash, size) = ParquetStore::hash_reader(input.source, input.cancel)?;
        check_hash(hash, size, input)?;
        report
    } else {
        let mut reader = HashingReader::new(&mut *input.source);
        let mut callback_failed = false;
        let result = decoder.decode_with_budget(
            DecodeInput::Reader(SourceInput {
                metadata,
                reader: &mut reader,
            }),
            input.decode_budget,
            &mut |record| {
                let outcome = emit(record);
                if outcome.is_err() {
                    callback_failed = true;
                }
                outcome
            },
        );
        if reader.io_failed {
            return Err(storage("source read failed"));
        }
        let report = source_result(
            input.relative_path,
            input.sample,
            input.cancel.is_cancelled(),
            result,
            callback_failed,
        )?;
        reader.drain(input.cancel)?;
        let size = reader.bytes;
        check_hash(reader.finish(), size, input)?;
        report
    };
    Ok(report)
}
fn source_result(
    relative_path: &str,
    sample: &[u8],
    cancelled: bool,
    result: Result<irmind_app::ParseReport, AppError>,
    callback_failed: bool,
) -> Result<irmind_app::ParseReport, AppError> {
    let report = match result {
        Err(AppError::Fixed(irmind_app::FixedAppError::SourceFormat)) if !callback_failed => {
            return Err(rejected(
                relative_path,
                sample,
                irmind_app::SourceFailureReason::Format,
                vec![],
            )?);
        }
        Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit)) if !callback_failed => {
            return Err(rejected(
                relative_path,
                sample,
                irmind_app::SourceFailureReason::Limit,
                vec![],
            )?);
        }
        Err(AppError::Cancelled) if !callback_failed && !cancelled => {
            return Err(rejected(
                relative_path,
                sample,
                irmind_app::SourceFailureReason::Cancelled,
                vec![],
            )?);
        }
        other => other?,
    };
    if report.accepted == 0 {
        return Err(rejected(
            relative_path,
            sample,
            irmind_app::SourceFailureReason::Format,
            report.samples.clone(),
        )?);
    }
    Ok(report)
}
fn check_hash(hash: [u8; 32], size: u64, input: &VerifiedInput<'_>) -> Result<(), AppError> {
    if hash != input.hash || size != input.size {
        return Err(AppError::EvidenceMismatch(input.hash_value.as_str().into()));
    }
    Ok(())
}
pub(in crate::parquet_store) fn projection_routes(
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

fn rejected(
    relative_path: &str,
    sample: &[u8],
    reason: irmind_app::SourceFailureReason,
    mut samples: Vec<String>,
) -> Result<AppError, AppError> {
    if samples.is_empty() {
        samples.push(
            String::from_utf8_lossy(&sample[..sample.len().min(256)])
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
    Ok(AppError::SourceFailure(
        irmind_app::RejectedSource::try_new(relative_path.into(), reason, samples)?,
    ))
}
