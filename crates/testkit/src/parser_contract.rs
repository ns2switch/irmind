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
