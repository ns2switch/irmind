use super::{
    AppError, BufRead, CancellationToken, MAX_RECORD_BYTES, MAX_SOURCE_BYTES, bounded_line, policy,
};

pub(super) fn csv_record(
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
pub(super) fn decode_csv(bytes: &[u8]) -> Result<::csv::StringRecord, AppError> {
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
