use super::SourceRecordError;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SourceDiscriminator {
    Dataset,
    Provider,
    Channel,
    RecordType,
}
impl SourceDiscriminator {
    pub const fn code(self) -> u8 {
        match self {
            Self::Dataset => 0,
            Self::Provider => 1,
            Self::Channel => 2,
            Self::RecordType => 3,
        }
    }
}

/// Only the immutable format descriptor gives meaning to timestamp fields/units.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceFormatV1 {
    id: String,
    version: String,
    discriminators: BTreeMap<SourceDiscriminator, String>,
}
impl std::fmt::Debug for SourceFormatV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceFormatV1")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}
impl SourceFormatV1 {
    pub fn try_new(
        id: &str,
        version: &str,
        discriminators: BTreeMap<SourceDiscriminator, String>,
    ) -> Result<Self, SourceRecordError> {
        if !identifier(id, 64)
            || !identifier(version, 128)
            || discriminators
                .values()
                .any(|v| v.is_empty() || v.len() > 256)
        {
            return Err(SourceRecordError::InvalidDescriptor);
        }
        Ok(Self {
            id: id.into(),
            version: version.into(),
            discriminators,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn discriminators(&self) -> &BTreeMap<SourceDiscriminator, String> {
        &self.discriminators
    }
    pub(super) fn encoded_len(&self) -> usize {
        24 + self.id.len()
            + self.version.len()
            + self
                .discriminators
                .values()
                .map(|v| 9 + v.len())
                .sum::<usize>()
    }
}
pub(super) fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
}
