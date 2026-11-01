use super::{
    AppError, BufRead, CancellationToken, GraphRecord, MAX_DEPTH, MAX_RECORD_BYTES, MAX_RECORDS,
    MAX_SOURCE_BYTES, ParseReport, ParserLocation, Provenance, SourceKind, Tainted,
    bounded_json_shape, mapping, policy, reject,
};

pub(super) fn parse_array(
    source: &str,
    reader: &mut impl BufRead,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut report = ParseReport {
        accepted: 0,
        rejected: 0,
        samples: Vec::new(),
    };
    let mut offset = 0u64;
    let mut index = 0usize;
    let first =
        next_nonspace(reader, &mut offset)?.ok_or_else(|| policy("empty Chainsaw array"))?;
    if first != b'[' {
        return Err(policy("invalid Chainsaw array"));
    }
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut marker = next_nonspace(reader, &mut offset)?
            .ok_or_else(|| policy("unterminated Chainsaw array"))?;
        if index > 0 {
            if marker == b']' {
                return Ok(report);
            }
            if marker != b',' {
                return Err(policy("Chainsaw array separator is missing"));
            }
            marker = next_nonspace(reader, &mut offset)?
                .ok_or_else(|| policy("unterminated Chainsaw array"))?;
        }
        if marker == b']' {
            if index == 0 {
                return Ok(report);
            }
            return Err(policy("Chainsaw array has a trailing comma"));
        }
        if marker != b'{' {
            return Err(policy("Chainsaw array requires objects"));
        }
        if index >= MAX_RECORDS {
            return Err(policy("Chainsaw record limit exceeded"));
        }
        let current = offset - 1;
        let object = read_object(reader, &mut offset, cancel)?;
        if object.len() > MAX_RECORD_BYTES || !bounded_json_shape(&object) {
            reject(&mut report, &object);
        } else if let Ok(record) = mapping::parse(&object, index) {
            let location = ParserLocation::new(source, "parser-chainsaw", current)
                .map_err(|_| policy("invalid parser source path"))?;
            emit(
                Tainted::from_external(
                    record,
                    Provenance::new(hash, Some(index as u64), SourceKind::File),
                )
                .with_parser_location(location),
            )?;
            report.accepted += 1;
        } else {
            reject(&mut report, &object);
        }
        index += 1;
    }
}
fn next_nonspace(reader: &mut impl BufRead, offset: &mut u64) -> Result<Option<u8>, AppError> {
    loop {
        let byte = next_byte(reader, offset)?;
        if byte.is_none_or(|value| !value.is_ascii_whitespace()) {
            return Ok(byte);
        }
    }
}
fn next_byte(reader: &mut impl BufRead, offset: &mut u64) -> Result<Option<u8>, AppError> {
    let bytes = reader
        .fill_buf()
        .map_err(|_| policy("cannot read Chainsaw source"))?;
    let Some(&byte) = bytes.first() else {
        return Ok(None);
    };
    reader.consume(1);
    *offset = offset.saturating_add(1);
    if *offset > MAX_SOURCE_BYTES {
        return Err(policy("Chainsaw source exceeds 50 GiB"));
    }
    Ok(Some(byte))
}
fn read_object(
    reader: &mut impl BufRead,
    offset: &mut u64,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    let mut bytes = vec![b'{'];
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let byte =
            next_byte(reader, offset)?.ok_or_else(|| policy("unterminated Chainsaw object"))?;
        if bytes.len() <= MAX_RECORD_BYTES {
            bytes.push(byte);
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(policy("Chainsaw object exceeds depth limit"));
                }
            }
            b'}' | b']' => {
                if depth == 0 {
                    return Err(policy("invalid Chainsaw nesting"));
                }
                depth -= 1;
                if depth == 0 {
                    return Ok(bytes);
                }
            }
            _ => {}
        }
    }
}
