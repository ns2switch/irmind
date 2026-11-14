use super::CatalogError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CatalogDigest([u8; 32]);
impl CatalogDigest {
    pub fn parse(text: &str) -> Result<Self, CatalogError> {
        if text.len() != 64 {
            return Err(CatalogError::InvalidData);
        }
        let bytes: [u8; 32] = hex::decode(text)
            .map_err(|_| CatalogError::InvalidData)?
            .try_into()
            .map_err(|_| CatalogError::InvalidData)?;
        if crate::hex(&bytes) != text {
            return Err(CatalogError::InvalidData);
        }
        Ok(Self(bytes))
    }
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl Serialize for CatalogDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::hex(&self.0))
    }
}
impl<'de> Deserialize<'de> for CatalogDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Methodology provenance identity; it is not an `EvidenceHash` or permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CatalogProofId(CatalogDigest);
impl CatalogProofId {
    pub fn parse(text: &str) -> Result<Self, CatalogError> {
        Ok(Self(CatalogDigest::parse(text)?))
    }
    pub(super) const fn from_digest(digest: CatalogDigest) -> Self {
        Self(digest)
    }
    pub const fn digest(&self) -> CatalogDigest {
        self.0
    }
}
