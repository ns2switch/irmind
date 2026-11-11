pub(super) fn hex(bytes: &str, limit: usize) -> Option<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > limit || !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| {
                char::from(byte)
                    .to_digit(16)
                    .and_then(|value| u8::try_from(value).ok())
            };
            Some(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}
