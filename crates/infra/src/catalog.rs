use ed25519_dalek::VerifyingKey;
use irmind_app::{
    AppError,
    catalog::{
        CatalogError, CatalogIndexBytes, CatalogIndexVerifier, FrozenCatalogRelease,
        VerifiedCatalogIndex,
    },
};
mod store;
pub use store::FileCatalogProofStore;

// Publisher keys enter only through a reviewed IRMind release. No synthetic
// fixture key, environment fallback or downloaded trust root is accepted here.
const RELEASE_CATALOG_KEYS: &[[u8; 32]] = &[];

pub struct Ed25519CatalogIndexVerifier {
    keys: &'static [[u8; 32]],
}
impl Ed25519CatalogIndexVerifier {
    pub fn production() -> Result<Self, CatalogError> {
        Self::from_release_keys(RELEASE_CATALOG_KEYS)
    }
    fn from_release_keys(keys: &'static [[u8; 32]]) -> Result<Self, CatalogError> {
        if keys.len() > 8 {
            return Err(CatalogError::InvalidData);
        }
        let mut seen = std::collections::BTreeSet::new();
        for bytes in keys {
            let key = VerifyingKey::from_bytes(bytes).map_err(|_| CatalogError::InvalidData)?;
            if key.is_weak() || !seen.insert(*bytes) {
                return Err(CatalogError::InvalidData);
            }
        }
        Ok(Self { keys })
    }
    pub fn available(&self) -> bool {
        !self.keys.is_empty()
    }
}
impl CatalogIndexVerifier for Ed25519CatalogIndexVerifier {
    fn verify(
        &self,
        bytes: &CatalogIndexBytes,
        expected: &FrozenCatalogRelease,
    ) -> Result<VerifiedCatalogIndex, AppError> {
        VerifiedCatalogIndex::authenticate(
            bytes,
            expected,
            self.keys,
            &crate::LocalVerifier {
                trusted: std::collections::BTreeMap::new(),
            },
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
