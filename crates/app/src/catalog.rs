//! Explicit catalog downloads and signed methodology provenance. Never evidence.
mod digest;
mod limits;
mod package;
mod schema;
mod store;
mod verified;
mod version;
pub use digest::{CatalogDigest, CatalogProofId};
pub use package::BoundedPackageBytes;
pub use schema::{CatalogCoverage, CatalogCoverageStatus, CatalogEntry, CatalogIndex};
pub use store::CatalogProofStore;
pub use verified::{
    CatalogAsset, CatalogIndexVerifier, VerifiedCatalogIndex, VerifiedCatalogRelease,
};
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CatalogError {
    #[error("catalog data is invalid or exceeds its bound")]
    InvalidData,
    #[error("the catalog has no compiled publisher keys")]
    Unavailable,
    #[error("the catalog publisher key is unknown or no longer accepted")]
    UntrustedKey,
    #[error("the catalog signature is invalid")]
    InvalidSignature,
    #[error("the catalog release does not match the frozen selection")]
    ReleaseMismatch,
    #[error("catalog package bytes do not match the signed index")]
    AssetMismatch,
}
impl From<CatalogError> for crate::AppError {
    fn from(error: CatalogError) -> Self {
        Self::Policy(error.to_string())
    }
}

pub const CATALOG_REPOSITORY: &str = "ns2switch/irmind-skills";
pub const MAX_CATALOG_INDEX_BYTES: usize = 1024 * 1024;

/// Untrusted bounded transport data, not an authenticated index.
pub struct CatalogIndexBytes {
    index: Vec<u8>,
    signature: [u8; 64],
}
impl CatalogIndexBytes {
    pub fn new(index: Vec<u8>, signature: &[u8]) -> Result<Self, CatalogError> {
        if index.is_empty() || index.len() > MAX_CATALOG_INDEX_BYTES {
            return Err(CatalogError::InvalidData);
        }
        Ok(Self {
            index,
            signature: signature
                .try_into()
                .map_err(|_| CatalogError::InvalidData)?,
        })
    }
    pub fn index(&self) -> &[u8] {
        &self.index
    }
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut bytes = b"irmind-skill-catalog-index-v1\0".to_vec();
        bytes.extend_from_slice(&(self.index.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.index);
        bytes
    }
    pub fn proof_id(&self) -> CatalogProofId {
        let mut bytes = b"irmind-skill-catalog-proof-v1\0".to_vec();
        bytes.extend_from_slice(&(self.index.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.index);
        bytes.extend_from_slice(&self.signature);
        CatalogProofId::from_digest(CatalogDigest::from_bytes(crate::sha256(&bytes)))
    }
}

/// An analyst-selected tag under the fixed catalog repository.
pub struct FrozenCatalogRelease {
    tag: String,
}
impl FrozenCatalogRelease {
    pub fn new(tag: &str) -> Result<Self, CatalogError> {
        version::release_tag(tag)?;
        Ok(Self { tag: tag.into() })
    }
    pub fn tag(&self) -> &str {
        &self.tag
    }
}
