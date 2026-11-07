use super::EventSchemaError;
use crate::EvidenceHash;

/// Corroborated against the signed source manifest at the application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventOrigin {
    source: EvidenceHash,
    record: u64,
    offset: Option<u64>,
    parser: String,
    parser_version: String,
}
impl EventOrigin {
    pub fn try_new(
        source: EvidenceHash,
        record: u64,
        offset: Option<u64>,
        parser: &str,
        parser_version: &str,
    ) -> Result<Self, EventSchemaError> {
        if parser.is_empty()
            || parser.len() > 64
            || !parser
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || parser_version.is_empty()
            || parser_version.len() > 128
            || !parser_version.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(EventSchemaError::InvalidOrigin);
        }
        Ok(Self {
            source,
            record,
            offset,
            parser: parser.to_owned(),
            parser_version: parser_version.to_owned(),
        })
    }
    pub(super) fn json_bytes(&self) -> usize {
        512 + self.parser.len() + self.parser_version.len() * 2
    }
    pub const fn source(&self) -> &EvidenceHash {
        &self.source
    }
    pub const fn record(&self) -> u64 {
        self.record
    }
    pub const fn offset(&self) -> Option<u64> {
        self.offset
    }
    pub fn parser(&self) -> &str {
        &self.parser
    }
    pub fn parser_version(&self) -> &str {
        &self.parser_version
    }
}
