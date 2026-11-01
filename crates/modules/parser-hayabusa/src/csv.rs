use super::{
    AppError, BufRead, CancellationToken, GraphRecord, MAX_FIELDS, MAX_RECORD_BYTES, MAX_RECORDS,
    MAX_SOURCE_BYTES, ParseReport, ParserLocation, Provenance, SourceKind, Tainted, bounded_line,
    mapping, policy, reject,
};

pub(super) fn parse_csv_lines(
    source: &str,
    reader: &mut impl BufRead,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let (header, consumed) = csv_record(reader, cancel)?;
    if consumed == 0 {
        return Err(policy("Hayabusa CSV header is missing"));
    }
    let headers = decode_csv(&header)?;
    if headers.len() > MAX_FIELDS
        || !["Timestamp", "RuleTitle", "Computer"]
            .iter()
            .all(|name| headers.iter().any(|header| header == *name))
    {
        return Err(policy("Hayabusa CSV header is invalid"));
    }
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut offset = consumed;
    let mut index = 0usize;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (row_bytes, size) = csv_record(reader, cancel)?;
        if size == 0 {
            return Ok(report);
        }
        if index >= MAX_RECORDS {
            return Err(policy("Hayabusa CSV record limit exceeded"));
        }
        let current = offset;
        offset = offset.saturating_add(size);
        if offset > MAX_SOURCE_BYTES {
            return Err(policy("Hayabusa CSV source exceeds 50 GiB"));
        }
        if row_bytes.len() > MAX_RECORD_BYTES {
            reject(&mut report, &row_bytes);
            index += 1;
            continue;
        }
        let parsed = decode_csv(&row_bytes).and_then(|row| {
            if row.len() > MAX_FIELDS || row.len() != headers.len() {
                return Err(policy("Hayabusa CSV field limit exceeded"));
            }
            mapping::parse_csv(index, &headers, &row)
        });
        match parsed {
            Ok(record) => {
                let location = ParserLocation::new(source, "parser-hayabusa", current)
                    .map_err(|_| policy("invalid parser source path"))?;
                emit(
                    Tainted::from_external(
                        record,
                        Provenance::new(hash, Some(index as u64), SourceKind::File),
                    )
                    .with_parser_location(location),
                )?;
                report.accepted += 1;
            }
            Err(_) => reject(&mut report, &row_bytes),
        }
        index += 1;
    }
}
fn csv_record(
    reader: &mut impl BufRead,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, u64), AppError> {
    let mut record = Vec::new();
    let mut consumed = 0u64;
    let mut quote_parity = false;
    loop {
        let (line, size, line_odd_quotes) = bounded_line(reader, cancel)?;
        if size == 0 {
            return Ok((record, consumed));
        }
        consumed = consumed.saturating_add(size);
        if consumed > MAX_SOURCE_BYTES {
            return Err(policy("Hayabusa CSV source exceeds 50 GiB"));
        }
        record.extend_from_slice(
            &line[..line.len().min(
                MAX_RECORD_BYTES
                    .saturating_add(1)
                    .saturating_sub(record.len()),
            )],
        );
        quote_parity ^= line_odd_quotes;
        if !quote_parity {
            return Ok((record, consumed));
        }
    }
}
fn decode_csv(bytes: &[u8]) -> Result<::csv::StringRecord, AppError> {
    let mut reader = ::csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(bytes);
    let row = reader
        .records()
        .next()
        .ok_or_else(|| policy("empty CSV record"))?
        .map_err(|_| policy("invalid CSV record"))?;
    if reader.records().next().is_some() {
        return Err(policy("unexpected extra CSV record"));
    }
    Ok(row)
}
