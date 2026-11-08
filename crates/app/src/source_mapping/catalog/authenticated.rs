use super::{Arc, BTreeMap, MappingCatalog, MappingError, SourceDecoder, SourceMapper};
use crate::source_mapping::{MappingProvenance, verify_mapping_installation};
use crate::{AppError, SignedOperation, Verifier};
use irmind_domain::EvidenceHash;

impl MappingCatalog {
    /// Installed definitions require their exact analyst-signed authorization.
    /// Authentication never executes a mapping or loads code from an export.
    pub fn freeze_authenticated(
        decoders: Vec<Arc<dyn SourceDecoder>>,
        mappings: Vec<Arc<dyn SourceMapper>>,
        proofs: &[SignedOperation],
        verifier: &dyn Verifier,
        analyst_key: &[u8],
    ) -> Result<Self, AppError> {
        let mut required = BTreeMap::new();
        for mapper in &mappings {
            if let MappingProvenance::InstalledDefinition { operation, .. } =
                mapper.manifest().provenance()
            {
                if required
                    .get(operation)
                    .is_some_and(|prior| *prior != mapper.manifest())
                {
                    return Err(MappingError::InvalidDefinition.into_app());
                }
                required.insert(operation.clone(), mapper.manifest());
            }
        }
        let mut authenticated = BTreeMap::new();
        for proof in proofs {
            let hash = EvidenceHash::from_bytes(proof.hash);
            let manifest = required
                .get(&hash)
                .ok_or_else(|| MappingError::InvalidDefinition.into_app())?;
            verify_mapping_installation(manifest, proof, verifier, analyst_key)?;
            if authenticated.insert(hash, proof.clone()).is_some() {
                return Err(MappingError::InvalidDefinition.into_app());
            }
        }
        if authenticated.len() != required.len() {
            return Err(MappingError::InvalidDefinition.into_app());
        }
        Self::freeze_verified(decoders, mappings, authenticated).map_err(MappingError::into_app)
    }

    /// Only signatures already authenticated when this immutable catalog was built.
    pub fn installation_proofs(&self) -> impl Iterator<Item = &SignedOperation> {
        self.proofs.values()
    }
}
