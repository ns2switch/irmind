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
const RELEASE_CATALOG_KEYS: &[[u8; 32]] = &[[
    251, 32, 21, 200, 61, 19, 254, 1, 142, 39, 10, 127, 231, 59, 247, 188, 207, 219, 98, 37, 101,
    227, 15, 122, 222, 67, 102, 55, 195, 178, 194, 91,
]];

#[derive(Clone)]
pub struct Ed25519CatalogIndexVerifier {
    keys: &'static [[u8; 32]],
}

impl crate::LocalStore {
    pub fn catalog_services(self: &std::sync::Arc<Self>) -> irmind_app::catalog::CatalogServices {
        irmind_app::catalog::CatalogServices::new(
            std::sync::Arc::new(self.catalog_verifier.clone()),
            self.clone(),
        )
    }
}

impl irmind_app::catalog::CatalogProofStore for crate::LocalStore {
    fn publish(
        &self,
        proof: &VerifiedCatalogIndex,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<irmind_app::catalog::CatalogProofId, AppError> {
        self.catalog_proofs.publish(proof, cancel)
    }
    fn read(
        &self,
        id: &irmind_app::catalog::CatalogProofId,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<CatalogIndexBytes, AppError> {
        self.catalog_proofs.read(id, cancel)
    }
    fn publish_for_case(
        &self,
        case: &irmind_domain::CaseId,
        proof: &VerifiedCatalogIndex,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<irmind_app::catalog::CatalogProofId, AppError> {
        self.catalog_proofs.publish_for_case(case, proof, cancel)
    }
    fn read_for_case(
        &self,
        case: &irmind_domain::CaseId,
        id: &irmind_app::catalog::CatalogProofId,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<CatalogIndexBytes, AppError> {
        self.catalog_proofs.read_for_case(case, id, cancel)
    }
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
    #[cfg(feature = "sigma")]
    pub fn verify_sigma(
        &self,
        index: &[u8],
        signature: &[u8],
        expected_tag: &str,
    ) -> Result<irmind_app::catalog::SigmaCatalogIndex, CatalogError> {
        irmind_app::catalog::SigmaCatalogIndex::authenticate(
            index,
            signature,
            expected_tag,
            self.keys,
            &crate::LocalVerifier {
                trusted: std::collections::BTreeMap::new(),
            },
        )
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
