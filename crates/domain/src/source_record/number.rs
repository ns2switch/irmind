use super::SourceRecordError;

/// An exact JSON decimal lexeme; no floating-point conversion is performed.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceNumber(String);

impl SourceNumber {
    pub fn try_new(value: &str) -> Result<Self, SourceRecordError> {
        if value.is_empty() || value.len() > 128 || !valid_number(value.as_bytes()) {
            return Err(SourceRecordError::InvalidNumber);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SourceNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceNumber(<source data>)")
    }
}

fn valid_number(mut bytes: &[u8]) -> bool {
    if bytes.first() == Some(&b'-') {
        bytes = &bytes[1..];
    }
    match bytes.first() {
        Some(b'0') => bytes = &bytes[1..],
        Some(b'1'..=b'9') => bytes = skip_digits(bytes),
        _ => return false,
    }
    if bytes.first() == Some(&b'.') {
        bytes = &bytes[1..];
        if !bytes.first().is_some_and(u8::is_ascii_digit) {
            return false;
        }
        bytes = skip_digits(bytes);
    }
    if matches!(bytes.first(), Some(b'e' | b'E')) {
        bytes = &bytes[1..];
        if matches!(bytes.first(), Some(b'+' | b'-')) {
            bytes = &bytes[1..];
        }
        if !bytes.first().is_some_and(u8::is_ascii_digit) {
            return false;
        }
        bytes = skip_digits(bytes);
    }
    bytes.is_empty()
}

fn skip_digits(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().take_while(|b| b.is_ascii_digit()).count()..]
}
