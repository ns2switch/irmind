//! Seekable-source variant of the common decoder/mapping contract.
use irmind_app::{
    AppError, CancellationToken, SourceDecoder, SourceMapper,
    source_mapping::{
        MappingCatalog, MappingOutput, SourceFileInput, SourceMetadata, SourceRecordAccumulator,
    },
};
use irmind_domain::SourceReferenceV1;
use std::{fs::File, io::Cursor, path::Path, sync::Arc};

pub fn run_source_file_mapping_contract(
    decoder: Arc<dyn SourceDecoder>,
    mappers: Vec<Arc<dyn SourceMapper>>,
    source: &str,
    fixture: &Path,
    expected: usize,
) -> Result<(), AppError> {
    let bytes = std::fs::read(fixture).map_err(|_| invalid())?;
    if bytes.len() > 1024 * 1024 || expected == 0 || expected > 100 {
        return Err(invalid());
    }
    let key = (
        decoder.identity().name.to_owned(),
        decoder.identity().version.to_owned(),
    );
    let catalog = MappingCatalog::freeze(vec![decoder], mappers).map_err(|_| invalid())?;
    let decoder = catalog.decoder(&key.0, &key.1).map_err(|_| invalid())?;
    let hash = irmind_app::sha256(&bytes);
    let first = projection(&catalog, decoder, fixture, source, hash, expected)?;
    if first != projection(&catalog, decoder, fixture, source, hash, expected)? {
        return Err(invalid());
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let reference = SourceReferenceV1::file(source).map_err(|_| invalid())?;
    let mut emitted = false;
    let result = decoder.decode_local_file(
        SourceFileInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: hash,
                time_context: None,
                cluster_context: None,
                cancel: &cancel,
            },
            file: &mut File::open(fixture).map_err(|_| invalid())?,
        },
        &mut |_| {
            emitted = true;
            Ok(())
        },
    );
    if emitted || !matches!(result, Err(AppError::Cancelled)) {
        return Err(invalid());
    }
    Ok(())
}
fn projection(
    catalog: &MappingCatalog,
    decoder: &dyn SourceDecoder,
    fixture: &Path,
    source: &str,
    hash: [u8; 32],
    expected: usize,
) -> Result<Vec<MappingOutput>, AppError> {
    let mut file = File::open(fixture).map_err(|_| invalid())?;
    let cancel = CancellationToken::new();
    let reference = SourceReferenceV1::file(source).map_err(|_| invalid())?;
    let metadata = SourceMetadata {
        source: &reference,
        evidence_hash: hash,
        time_context: None,
        cluster_context: None,
        cancel: &cancel,
    };
    let mut accumulator = SourceRecordAccumulator::new(
        metadata,
        decoder.identity(),
        file.metadata().map_err(|_| invalid())?.len(),
        catalog,
    )?;
    let mut tuples = Cursor::new(Vec::new());
    let mut outputs = Vec::new();
    let report = decoder.decode_local_file(
        SourceFileInput {
            metadata,
            file: &mut file,
        },
        &mut |record| {
            if outputs.len() == expected {
                return Err(invalid());
            }
            let mapped = accumulator.accept(&record, &mut tuples)?;
            if mapped.identity.is_none() || mapped.output.provenance() != record.provenance() {
                return Err(invalid());
            }
            mapped.output.inspect(|output| outputs.push(output.clone()));
            Ok(())
        },
    )?;
    accumulator.finish(&mut tuples, &report)?;
    if report.accepted != expected || report.rejected != 0 || outputs.len() != expected {
        return Err(invalid());
    }
    Ok(outputs)
}
fn invalid() -> AppError {
    AppError::Policy("seekable source mapping contract failed".into())
}
