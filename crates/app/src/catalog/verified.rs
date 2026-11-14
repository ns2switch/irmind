use super::{
    CatalogDigest, CatalogEntry, CatalogError, CatalogIndex, CatalogIndexBytes, CatalogProofId,
    FrozenCatalogRelease, limits,
};
use crate::{AppError, Verifier};

#[derive(serde::Deserialize)]
struct Header {
    key_id: CatalogDigest,
}

/// Authenticated data, not Analyst admission or a grant of tool permissions.
pub struct VerifiedCatalogIndex {
    raw: CatalogIndexBytes,
    index: CatalogIndex,
    keyset: CatalogDigest,
}
impl VerifiedCatalogIndex {
    /// Native adapters supply release-compiled keys, never packet/config keys.
    /// The production adapter also rejects invalid/weak keys at construction.
    pub fn authenticate(
        raw: &CatalogIndexBytes,
        expected: &FrozenCatalogRelease,
        release_keys: &'static [[u8; 32]],
        verifier: &dyn Verifier,
    ) -> Result<Self, CatalogError> {
        if release_keys.is_empty() {
            return Err(CatalogError::Unavailable);
        }
        if release_keys.len() > 8 {
            return Err(CatalogError::InvalidData);
        }
        let mut keys = release_keys
            .iter()
            .map(|key| (crate::sha256(key), key))
            .collect::<Vec<_>>();
        keys.sort_by_key(|(id, _)| *id);
        if keys.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(CatalogError::InvalidData);
        }
        limits::check(raw.index())?;
        let header: Header =
            serde_json::from_slice(raw.index()).map_err(|_| CatalogError::InvalidData)?;
        let key = keys
            .iter()
            .find(|(id, _)| id == header.key_id.as_bytes())
            .ok_or(CatalogError::UntrustedKey)?
            .1;
        verifier
            .verify(key, &raw.signature_preimage(), raw.signature())
            .map_err(|_| CatalogError::InvalidSignature)?;
        let index = CatalogIndex::decode_untrusted(raw.index())?;
        if index.tag() != expected.tag() {
            return Err(CatalogError::ReleaseMismatch);
        }
        let mut preimage = b"irmind-catalog-keyset-v1\0".to_vec();
        preimage.extend_from_slice(&(keys.len() as u64).to_be_bytes());
        for (_, key) in &keys {
            preimage.extend_from_slice(*key);
        }
        Ok(Self {
            raw: CatalogIndexBytes::new(raw.index().to_vec(), raw.signature())?,
            index,
            keyset: CatalogDigest::from_bytes(crate::sha256(&preimage)),
        })
    }
    pub const fn index(&self) -> &CatalogIndex {
        &self.index
    }
    pub const fn raw(&self) -> &CatalogIndexBytes {
        &self.raw
    }
    pub fn proof_id(&self) -> CatalogProofId {
        self.raw.proof_id()
    }
    pub const fn keyset_hash(&self) -> CatalogDigest {
        self.keyset
    }
    pub fn index_hash(&self) -> CatalogDigest {
        CatalogDigest::from_bytes(crate::sha256(self.raw.index()))
    }
    pub fn release(&self) -> VerifiedCatalogRelease {
        VerifiedCatalogRelease {
            tag: self.index.tag().into(),
            commit: self.index.commit().into(),
            sequence: self.index.sequence(),
            index_hash: self.index_hash(),
        }
    }
    pub fn asset(&self, name: &str) -> Result<CatalogAsset, CatalogError> {
        let entry = self
            .index
            .entries()
            .iter()
            .find(|entry| entry.name() == name)
            .ok_or(CatalogError::InvalidData)?;
        Ok(CatalogAsset {
            entry: entry.clone(),
            index_hash: self.index_hash(),
        })
    }
}

pub trait CatalogIndexVerifier: Send + Sync {
    fn verify(
        &self,
        bytes: &CatalogIndexBytes,
        expected: &FrozenCatalogRelease,
    ) -> Result<VerifiedCatalogIndex, AppError>;
}

/// Frozen publisher claims, not independently verified GitHub provenance.
pub struct VerifiedCatalogRelease {
    tag: String,
    commit: String,
    sequence: u64,
    index_hash: CatalogDigest,
}
impl VerifiedCatalogRelease {
    pub fn tag(&self) -> &str {
        &self.tag
    }
    pub fn commit(&self) -> &str {
        &self.commit
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn index_hash(&self) -> CatalogDigest {
        self.index_hash
    }
}

pub struct CatalogAsset {
    entry: CatalogEntry,
    index_hash: CatalogDigest,
}
impl CatalogAsset {
    pub const fn entry(&self) -> &CatalogEntry {
        &self.entry
    }
    pub const fn index_hash(&self) -> CatalogDigest {
        self.index_hash
    }
    pub fn check_bytes(&self, bytes: &[u8]) -> Result<(), CatalogError> {
        if bytes.len() as u64 != self.entry.asset_bytes()
            || &crate::sha256(bytes) != self.entry.asset_hash().as_bytes()
        {
            return Err(CatalogError::AssetMismatch);
        }
        Ok(())
    }
}
