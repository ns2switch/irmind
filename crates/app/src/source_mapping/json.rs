//! Bounded original JSON fields, including exact decimal lexemes and duplicate checks.
mod read;
mod write;
use super::{SourceRecordError, SourceValue};
use irmind_domain::{SOURCE_MAX_BYTES, SOURCE_MAX_DEPTH, SOURCE_MAX_NODES};

#[derive(Clone, Copy)]
pub struct SourceJsonLimits {
    pub bytes: usize,
    pub nodes: usize,
    pub fields: usize,
    pub depth: usize,
}
impl Default for SourceJsonLimits {
    fn default() -> Self {
        Self {
            bytes: SOURCE_MAX_BYTES,
            nodes: SOURCE_MAX_NODES,
            fields: 1024,
            depth: SOURCE_MAX_DEPTH,
        }
    }
}
impl SourceJsonLimits {
    fn validate(self) -> Result<Self, SourceRecordError> {
        if self.bytes == 0
            || self.bytes > SOURCE_MAX_BYTES
            || self.nodes == 0
            || self.nodes > SOURCE_MAX_NODES
            || self.fields == 0
            || self.fields > SOURCE_MAX_NODES
            || self.depth == 0
            || self.depth > SOURCE_MAX_DEPTH
        {
            return Err(SourceRecordError::Limit);
        }
        Ok(self)
    }
}

pub fn decode_json_fields(
    input: &[u8],
    limits: SourceJsonLimits,
) -> Result<SourceValue, SourceRecordError> {
    read::decode(input, limits.validate()?)
}

/// Validate discarded container metadata with the same bounded JSON grammar.
pub fn validate_json_value(
    input: &[u8],
    limits: SourceJsonLimits,
) -> Result<(), SourceRecordError> {
    read::parse(input, limits.validate()?).map(|_| ())
}

/// Display/search projection only. Source hashes use the typed canonical codec.
/// Binary values have an explicit hexadecimal display wrapper.
pub fn render_source_fields(fields: &SourceValue) -> Result<String, SourceRecordError> {
    fields.validate()?;
    write::render(fields)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
