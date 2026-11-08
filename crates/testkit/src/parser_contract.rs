use irmind_app::{AppError, CancellationToken, GraphRelation, LogParser, Provenance, sha256};
use std::io::Cursor;

type Row = (
    usize,
    String,
    String,
    String,
    Vec<(String, String)>,
    Vec<GraphRelation>,
    Provenance,
);

/// Offline streaming contract for a small public synthetic fixture.
pub fn run_log_parser_contract(
    parser: &dyn LogParser,
    source: &str,
    fixture: &[u8],
    expected: usize,
) -> Result<(), AppError> {
    if fixture.len() > 64 * 1024
        || expected == 0
        || expected > 100
        || parser.identity().name.is_empty()
        || parser.identity().version.is_empty()
        || parser.detect(source, fixture).is_none()
    {
        return Err(contract_error());
    }
    let first = parse(parser, source, fixture, expected)?;
    let second = parse(parser, source, fixture, expected)?;
    if first != second {
        return Err(contract_error());
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut emitted = false;
    if !matches!(
        parser.parse_reader_report(
            source,
            &mut Cursor::new(fixture),
            sha256(fixture),
            &cancel,
            &mut |_| {
                emitted = true;
                Ok(())
            }
        ),
        Err(AppError::Cancelled)
    ) || emitted
    {
        return Err(contract_error());
    }
    Ok(())
}

fn parse(
    parser: &dyn LogParser,
    source: &str,
    fixture: &[u8],
    expected: usize,
) -> Result<Vec<Row>, AppError> {
    let hash = sha256(fixture);
    let mut rows = Vec::new();
    let report = parser.parse_reader_report(
        source,
        &mut Cursor::new(fixture),
        hash,
        &CancellationToken::new(),
        &mut |row| {
            if rows.len() >= expected || row.provenance().evidence_hash() != &hash {
                return Err(contract_error());
            }
            row.inspect(|record| {
                rows.push((
                    record.index,
                    record.at.clone(),
                    record.event.clone(),
                    record.text.clone(),
                    record.entities.clone(),
                    record.relations.clone(),
                    row.provenance().clone(),
                ));
            });
            Ok(())
        },
    )?;
    if report.accepted != expected || report.rejected != 0 || rows.len() != expected {
        return Err(contract_error());
    }
    Ok(rows)
}
fn contract_error() -> AppError {
    AppError::Policy("streaming parser contract failed".into())
}

/// Contract for binary parsers that require the authenticated regular-file route.
/// Detection still sees at most 64 KiB; no system-temporary copy is made.
pub fn run_seekable_log_parser_contract(
    parser: &dyn LogParser,
    source: &str,
    file: &mut std::fs::File,
    expected: usize,
) -> Result<(), AppError> {
    use std::io::{Read as _, Seek as _};
    if file.metadata().map_err(|_| contract_error())?.len() > 1024 * 1024
        || expected == 0
        || expected > 100
    {
        return Err(contract_error());
    }
    file.rewind().map_err(|_| contract_error())?;
    let mut fixture = Vec::new();
    file.read_to_end(&mut fixture)
        .map_err(|_| contract_error())?;
    let sample = &fixture[..fixture.len().min(64 * 1024)];
    if parser.detect(source, sample).is_none() {
        return Err(contract_error());
    }
    let hash = sha256(&fixture);
    let mut previous = None;
    for _ in 0..2 {
        file.rewind().map_err(|_| contract_error())?;
        let mut rows = Vec::new();
        let report = parser.parse_local_file_report(
            source,
            file,
            hash,
            &CancellationToken::new(),
            &mut |row| {
                if rows.len() >= expected || row.provenance().evidence_hash() != &hash {
                    return Err(contract_error());
                }
                row.inspect(|r| {
                    rows.push((
                        r.index,
                        r.at.clone(),
                        r.event.clone(),
                        r.text.clone(),
                        r.entities.clone(),
                        r.relations.clone(),
                        row.provenance().clone(),
                    ));
                });
                Ok(())
            },
        )?;
        if report.accepted != expected || report.rejected != 0 || rows.len() != expected {
            return Err(contract_error());
        }
        if previous.as_ref().is_some_and(|old| old != &rows) {
            return Err(contract_error());
        }
        previous = Some(rows);
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    if !matches!(
        parser.parse_local_file_report(source, file, hash, &cancel, &mut |_| Err(contract_error())),
        Err(AppError::Cancelled)
    ) {
        return Err(contract_error());
    }
    Ok(())
}
