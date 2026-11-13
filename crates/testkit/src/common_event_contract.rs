//! Shared contracts exercise the decoder/mapping boundary, not a parser bridge.
use irmind_app::source_mapping::{
    MappingCatalog, MappingOutput, SourceInput, SourceMetadata, SourceRecordAccumulator,
    SourceReferenceV1,
};
use irmind_app::{AppError, CancellationToken, SourceDecoder, SourceMapper};
use std::{io::Cursor, sync::Arc};

pub fn run_source_mapping_contract(
    decoder: Arc<dyn SourceDecoder>,
    mapper: Arc<dyn SourceMapper>,
    source: &str,
    fixture: &[u8],
    expected: usize,
) -> Result<(), AppError> {
    if fixture.len() > 64 * 1024 || expected == 0 || expected > 100 {
        return Err(invalid());
    }
    let identity = decoder.identity();
    let key = (identity.name.to_owned(), identity.version.to_owned());
    let catalog = MappingCatalog::freeze(vec![decoder], vec![mapper]).map_err(|_| invalid())?;
    let decoder = catalog.decoder(&key.0, &key.1).map_err(|_| invalid())?;
    let first = projection(&catalog, decoder, source, fixture, expected)?;
    if first != projection(&catalog, decoder, source, fixture, expected)? {
        return Err(invalid());
    }
    std::thread::scope(|scope| {
        let workers = (0..4)
            .map(|_| scope.spawn(|| projection(&catalog, decoder, source, fixture, expected)))
            .collect::<Vec<_>>();
        for worker in workers {
            if worker.join().map_err(|_| invalid())?? != first {
                return Err(invalid());
            }
        }
        Ok(())
    })?;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let reference = SourceReferenceV1::file(source).map_err(|_| invalid())?;
    let mut emitted = false;
    let result = decoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: irmind_app::sha256(fixture),
                time_context: None,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut Cursor::new(fixture),
        },
        &mut |_| {
            emitted = true;
            Ok(())
        },
    );
    if !matches!(result, Err(AppError::Cancelled)) || emitted {
        return Err(invalid());
    }
    Ok(())
}
fn projection(
    catalog: &MappingCatalog,
    decoder: &dyn SourceDecoder,
    source: &str,
    fixture: &[u8],
    expected: usize,
) -> Result<Vec<MappingOutput>, AppError> {
    let cancel = CancellationToken::new();
    let reference = SourceReferenceV1::file(source).map_err(|_| invalid())?;
    let metadata = SourceMetadata {
        source: &reference,
        evidence_hash: irmind_app::sha256(fixture),
        time_context: None,
        cluster_context: None,
        cancel: &cancel,
    };
    let mut accumulator =
        SourceRecordAccumulator::new(metadata, decoder.identity(), fixture.len() as u64, catalog)?;
    let mut tuples = Cursor::new(Vec::new());
    let mut outputs = Vec::new();
    let report = decoder.decode_reader(
        SourceInput {
            metadata,
            reader: &mut Cursor::new(fixture),
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
    AppError::Policy("source mapping contract failed".into())
}
