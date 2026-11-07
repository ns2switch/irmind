//! Bounded offline checks shared by every typed parser and its bridge.
use irmind_app::{
    AppError, CancellationToken, StreamingEventParser, encode_common_event, validate_common_record,
};
use std::io::Cursor;

pub fn run_common_event_contract(
    parser: &dyn StreamingEventParser,
    source: &str,
    fixture: &[u8],
    expected: usize,
) -> Result<(), AppError> {
    if fixture.len() > 64 * 1024 || expected == 0 || expected > 100 {
        return Err(invalid());
    }
    let first = projection(parser, source, fixture, expected)?;
    if first != projection(parser, source, fixture, expected)? {
        return Err(invalid());
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut emitted = false;
    let result = parser.parse_common_reader_report(
        source,
        &mut Cursor::new(fixture),
        irmind_app::sha256(fixture),
        &cancel,
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
    parser: &dyn StreamingEventParser,
    source: &str,
    fixture: &[u8],
    expected: usize,
) -> Result<Vec<String>, AppError> {
    let hash = irmind_app::sha256(fixture);
    let identity = parser.identity_for_source(source)?;
    let mut rows = Vec::new();
    let report = parser.parse_common_reader_report(
        source,
        &mut Cursor::new(fixture),
        hash,
        &CancellationToken::new(),
        &mut |tainted| {
            if rows.len() == expected || tainted.provenance().evidence_hash() != &hash {
                return Err(invalid());
            }
            let mut result = None;
            tainted.inspect(|record| {
                result = Some(
                    validate_common_record(record, tainted.provenance(), identity)
                        .and_then(|()| encode_common_event(&record.common)),
                );
            });
            rows.push(result.ok_or_else(invalid)??);
            Ok(())
        },
    )?;
    if rows.len() != expected || report.accepted != expected || report.rejected != 0 {
        return Err(invalid());
    }
    Ok(rows)
}
fn invalid() -> AppError {
    AppError::Policy("common event contract failed".into())
}
