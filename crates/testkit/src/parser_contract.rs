//! Detector and original-field decoder contracts; projections belong to mappings.
use irmind_app::source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1};
use irmind_app::{AppError, CancellationToken, LogParser, ParserTimeContext, SourceDecoder};
use std::io::Cursor;

/// Offline contract for a bounded public synthetic fixture.
pub fn run_log_parser_contract(
    parser: &dyn LogParser,
    decoder: &dyn SourceDecoder,
    source: &str,
    fixture: &[u8],
    expected: usize,
    context: Option<&ParserTimeContext>,
) -> Result<(), AppError> {
    if fixture.len() > 64 * 1024
        || expected == 0
        || expected > 100
        || decoder.identity().name.is_empty()
        || decoder.identity().version.is_empty()
        || parser.detect(source, fixture).is_none()
    {
        return Err(contract_error());
    }
    let first = parse(decoder, source, fixture, expected, context)?;
    if first != parse(decoder, source, fixture, expected, context)? {
        return Err(contract_error());
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let reference = SourceReferenceV1::file(source).map_err(|_| contract_error())?;
    let mut emitted = false;
    let result = decoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: irmind_app::sha256(fixture),
                time_context: context,
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
        return Err(contract_error());
    }
    Ok(())
}

fn parse(
    decoder: &dyn SourceDecoder,
    source: &str,
    fixture: &[u8],
    expected: usize,
    context: Option<&ParserTimeContext>,
) -> Result<Vec<SourceRecordV1>, AppError> {
    let hash = irmind_app::sha256(fixture);
    let cancel = CancellationToken::new();
    let reference = SourceReferenceV1::file(source).map_err(|_| contract_error())?;
    let mut rows = Vec::new();
    let report = decoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: hash,
                time_context: context,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut Cursor::new(fixture),
        },
        &mut |row| {
            if rows.len() >= expected || row.provenance().evidence_hash() != &hash {
                return Err(contract_error());
            }
            row.inspect(|record| rows.push(record.clone()));
            Ok(())
        },
    )?;
    if report.accepted != expected || report.rejected != 0 || rows.len() != expected {
        return Err(contract_error());
    }
    Ok(rows)
}
fn contract_error() -> AppError {
    AppError::Policy("source parser contract failed".into())
}

/// Feed a synthetic reader through the real current decoder with explicit provenance.
pub fn decode_source(
    decoder: &dyn SourceDecoder,
    source: &str,
    reader: &mut dyn std::io::Read,
    evidence_hash: [u8; 32],
    cancel: &CancellationToken,
    context: Option<&ParserTimeContext>,
    emit: &mut dyn FnMut(irmind_domain::Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<irmind_app::ParseReport, AppError> {
    let reference = SourceReferenceV1::file(source).map_err(|_| contract_error())?;
    decoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash,
                time_context: context,
                cluster_context: None,
                cancel,
            },
            reader,
        },
        emit,
    )
}
