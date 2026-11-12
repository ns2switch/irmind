//! Faithful bounded decoding, independent of classifications and mapping versions.
mod canonical;
mod error;
mod format;
mod number;
mod path;
mod reference;
mod value;

use crate::{EventOrigin, IndexedTime};
pub use error::SourceRecordError;
pub use format::{SourceDiscriminator, SourceFormatV1};
pub use number::SourceNumber;
pub use path::{SourcePath, SourcePathSegment};
pub use reference::SourceReferenceV1;
pub use value::SourceValue;

pub const SOURCE_RECORD_V1: &str = "irmind-source-record-v1";
pub const SOURCE_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const SOURCE_MAX_NODES: usize = 4096;
pub const SOURCE_MAX_DEPTH: usize = 32;

/// Optional references to original grouped members, never synthetic byte offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceMemberV1 {
    pub ordinal: u64,
    pub offset: Option<u64>,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct DecodeAnnotationsV1 {
    partial: bool,
    members: Vec<SourceMemberV1>,
    raw: Option<String>,
}
impl DecodeAnnotationsV1 {
    pub fn try_new(
        partial: bool,
        members: Vec<SourceMemberV1>,
        raw: Option<String>,
    ) -> Result<Self, SourceRecordError> {
        if members.len() > 256
            || !members.windows(2).all(|m| m[0].ordinal < m[1].ordinal)
            || raw.as_ref().is_some_and(|r| r.len() > SOURCE_MAX_BYTES)
        {
            return Err(SourceRecordError::Limit);
        }
        Ok(Self {
            partial,
            members,
            raw,
        })
    }
    pub const fn partial(&self) -> bool {
        self.partial
    }
    pub fn members(&self) -> &[SourceMemberV1] {
        &self.members
    }
    pub fn raw(&self) -> Option<&str> {
        self.raw.as_deref()
    }
}

/// A checked representation is still untrusted and must remain wrapped in Tainted.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceRecordV1 {
    origin: EventOrigin,
    source: SourceReferenceV1,
    timestamp: Option<IndexedTime>,
    format: SourceFormatV1,
    fields: SourceValue,
    annotations: DecodeAnnotationsV1,
    // Scheduling metadata only: deliberately absent from the canonical codec.
    retained_bytes: usize,
}
impl std::fmt::Debug for SourceRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceRecordV1")
            .field("origin", &self.origin)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}
impl SourceRecordV1 {
    pub fn try_new(
        origin: EventOrigin,
        source: &str,
        timestamp: Option<IndexedTime>,
        format: SourceFormatV1,
        fields: SourceValue,
        annotations: DecodeAnnotationsV1,
    ) -> Result<Self, SourceRecordError> {
        Self::try_from_source(
            origin,
            SourceReferenceV1::file(source)?,
            timestamp,
            format,
            fields,
            annotations,
        )
    }

    pub fn try_from_source(
        origin: EventOrigin,
        source: SourceReferenceV1,
        timestamp: Option<IndexedTime>,
        format: SourceFormatV1,
        fields: SourceValue,
        annotations: DecodeAnnotationsV1,
    ) -> Result<Self, SourceRecordError> {
        if !matches!(fields, SourceValue::Object(_)) {
            return Err(SourceRecordError::InvalidDescriptor);
        }
        let (field_bytes, nodes) = fields.measured_size()?;
        let estimated = field_bytes
            + 512
            + source.reference().len()
            + origin.parser().len()
            + origin.parser_version().len()
            + format.encoded_len()
            + annotations.members.len() * 18
            + annotations.raw.as_ref().map_or(0, String::len);
        if estimated > SOURCE_MAX_BYTES {
            return Err(SourceRecordError::Limit);
        }
        Ok(Self {
            origin,
            source,
            timestamp,
            format,
            fields,
            annotations,
            retained_bytes: estimated * 2 + nodes * 256 + 8192,
        })
    }
    /// Conservative bounded-queue charge, independent of signed encoding.
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
    pub const fn origin(&self) -> &EventOrigin {
        &self.origin
    }
    pub fn source(&self) -> &str {
        self.source.reference()
    }
    pub const fn reference(&self) -> &SourceReferenceV1 {
        &self.source
    }
    pub const fn timestamp(&self) -> Option<IndexedTime> {
        self.timestamp
    }
    pub const fn format(&self) -> &SourceFormatV1 {
        &self.format
    }
    pub const fn fields(&self) -> &SourceValue {
        &self.fields
    }
    pub const fn annotations(&self) -> &DecodeAnnotationsV1 {
        &self.annotations
    }
    /// Tagged, length-prefixed, lexically ordered input to the source commitment.
    pub fn feed_canonical(&self, feed: &mut dyn FnMut(&[u8])) {
        canonical::record(self, feed);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
