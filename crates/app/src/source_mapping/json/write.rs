use super::{SourceRecordError, SourceValue};
use std::fmt::Write as _;

pub(super) fn render(value: &SourceValue, capacity: usize) -> Result<String, SourceRecordError> {
    let mut output = String::with_capacity(capacity);
    write(value, &mut output)?;
    Ok(output)
}
fn quoted(value: &str, output: &mut String) -> Result<(), SourceRecordError> {
    serde_json::to_writer(Append(output), value).map_err(|_| SourceRecordError::InvalidEncoding)
}
/// String fragments emitted by `serde_json` remain UTF-8. Append to the shared
/// output buffer instead of allocating a temporary JSON string for every field.
struct Append<'a>(&'a mut String);
impl std::io::Write for Append<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        self.0.push_str(text);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn write(value: &SourceValue, output: &mut String) -> Result<(), SourceRecordError> {
    match value {
        SourceValue::Null => output.push_str("null"),
        SourceValue::Boolean(true) => output.push_str("true"),
        SourceValue::Boolean(false) => output.push_str("false"),
        SourceValue::Number(number) => output.push_str(number.as_str()),
        SourceValue::Text(value) => quoted(value, output)?,
        SourceValue::Bytes(bytes) => {
            output.push_str("{\"$irmind_bytes_hex\":\"");
            for byte in bytes {
                write!(output, "{byte:02x}").map_err(|_| SourceRecordError::InvalidEncoding)?;
            }
            output.push_str("\"}");
        }
        SourceValue::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write(value, output)?;
            }
            output.push(']');
        }
        SourceValue::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                quoted(key, output)?;
                output.push(':');
                write(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}
