use crate::{COMMON_EVENT_V1, EvidenceHash, SourceRecordError};

/// Identity of one immutable reviewed implementation, never a loadable path.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MappingIdentityV1 {
    id: String,
    version: String,
    target: String,
    implementation: EvidenceHash,
}

impl MappingIdentityV1 {
    pub fn try_new(
        id: &str,
        version: &str,
        target: &str,
        implementation: EvidenceHash,
    ) -> Result<Self, SourceRecordError> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || version.is_empty()
            || version.len() > 128
            || !version.bytes().all(|b| b.is_ascii_graphic())
            || target != COMMON_EVENT_V1
        {
            return Err(SourceRecordError::InvalidDescriptor);
        }
        Ok(Self {
            id: id.into(),
            version: version.into(),
            target: target.into(),
            implementation,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub const fn implementation(&self) -> &EvidenceHash {
        &self.implementation
    }
    pub fn feed_canonical(&self, feed: &mut dyn FnMut(&[u8])) {
        feed(b"irmind-mapping-identity-v1\0");
        for value in [&self.id, &self.version, &self.target] {
            feed(&(value.len() as u64).to_be_bytes());
            feed(value.as_bytes());
        }
        feed(self.implementation.as_str().as_bytes());
    }
}
