use super::EventSchemaError;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct EventText(String);
impl EventText {
    pub fn new(value: &str) -> Result<Self, EventSchemaError> {
        if value.is_empty() || value.len() > 8192 || value.contains('\0') {
            return Err(EventSchemaError::InvalidValue);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn identifier(value: &str) -> Result<Self, EventSchemaError> {
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(EventSchemaError::InvalidValue);
        }
        Self::new(value)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(super) fn json_bytes(&self) -> usize {
        2 + self
            .0
            .chars()
            .map(|c| match c {
                '\n' | '\r' | '\t' | '\u{0008}' | '\u{000c}' | '"' | '\\' => 2,
                c if c < '\u{0020}' => 6,
                c => c.len_utf8(),
            })
            .sum::<usize>()
    }
}
impl std::fmt::Debug for EventText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EventText(<redacted>)")
    }
}
