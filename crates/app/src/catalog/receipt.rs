use super::{
    CATALOG_REPOSITORY, CatalogDigest, CatalogError, CatalogProofId, VerifiedCatalogIndex, limits,
    schema, version,
};
use crate::CompiledSkill;
use serde::{Deserialize, Serialize};

/// Publisher provenance, distinct from evidence and from Analyst admission.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReceipt {
    catalog: String,
    release_tag: String,
    release_commit: String,
    release_sequence: u64,
    key_id: CatalogDigest,
    index_sha256: CatalogDigest,
    proof_sha256: CatalogDigest,
    entry_sha256: CatalogDigest,
    asset: String,
    asset_sha256: CatalogDigest,
    asset_bytes: u64,
    verification_policy: String,
    keyset_sha256: CatalogDigest,
    offline: bool,
    downgrade_confirmed: bool,
}
impl CatalogReceipt {
    pub fn new(
        index: &VerifiedCatalogIndex,
        name: &str,
        offline: bool,
        downgrade_confirmed: bool,
    ) -> Result<Self, CatalogError> {
        let asset = index.asset(name)?;
        let entry = asset.entry();
        let receipt = Self {
            catalog: CATALOG_REPOSITORY.into(),
            release_tag: index.index().tag().into(),
            release_commit: index.index().commit().into(),
            release_sequence: index.index().sequence(),
            key_id: index.index().key_id(),
            index_sha256: index.index_hash(),
            proof_sha256: index.proof_id().digest(),
            entry_sha256: entry.identity()?,
            asset: entry.asset().into(),
            asset_sha256: entry.asset_hash(),
            asset_bytes: entry.asset_bytes(),
            verification_policy: "compiled-ed25519-v1".into(),
            keyset_sha256: index.keyset_hash(),
            offline,
            downgrade_confirmed,
        };
        receipt.validate()?;
        Ok(receipt)
    }
    /// Bounded structure only. Its index must still pass publisher verification.
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.len() > 4096 {
            return Err(CatalogError::InvalidData);
        }
        limits::check(bytes)?;
        let receipt: Self = serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidData)?;
        receipt.validate()?;
        if receipt.canonical()? != bytes {
            return Err(CatalogError::InvalidData);
        }
        Ok(receipt)
    }
    pub fn canonical(&self) -> Result<Vec<u8>, CatalogError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| CatalogError::InvalidData)
    }
    pub fn identity(&self) -> Result<CatalogDigest, CatalogError> {
        let mut bytes = b"irmind-skill-catalog-receipt-v1\0".to_vec();
        bytes.extend(self.canonical()?);
        Ok(CatalogDigest::from_bytes(crate::sha256(&bytes)))
    }
    pub fn validate(&self) -> Result<(), CatalogError> {
        version::release_tag(&self.release_tag)?;
        if self.catalog != CATALOG_REPOSITORY
            || self.release_sequence == 0
            || self.release_commit.len() != 40
            || !self
                .release_commit
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || !schema::asset_name(&self.asset)
            || self.asset_bytes == 0
            || self.asset_bytes > 1024 * 1024
            || self.verification_policy != "compiled-ed25519-v1"
        {
            return Err(CatalogError::InvalidData);
        }
        Ok(())
    }
    pub fn check(
        &self,
        index: &VerifiedCatalogIndex,
        skill: &CompiledSkill,
    ) -> Result<(), CatalogError> {
        self.validate()?;
        let asset = index.asset(skill.metadata().name().as_str())?;
        let entry = asset.entry();
        if self.release_tag != index.index().tag()
            || self.release_commit != index.index().commit()
            || self.release_sequence != index.index().sequence()
            || self.key_id != index.index().key_id()
            || self.index_sha256 != index.index_hash()
            || self.proof_id() != index.proof_id()
            || self.entry_sha256 != entry.identity()?
            || self.asset != entry.asset()
            || self.asset_sha256 != entry.asset_hash()
            || self.asset_bytes != entry.asset_bytes()
            || skill.package().hash().as_bytes() != entry.package_hash().as_bytes()
            || skill.metadata().version().as_str() != entry.version()
            || !skill
                .metadata()
                .sources()
                .iter()
                .map(String::as_str)
                .eq(entry.sources().iter().map(String::as_str))
        {
            return Err(CatalogError::InvalidData);
        }
        // The producing keyset is an authenticated decision record, not a trust
        // root. Adding a compiled key must not invalidate a still-accepted signer.
        Ok(())
    }
    pub const fn proof_id(&self) -> CatalogProofId {
        CatalogProofId::from_digest(self.proof_sha256)
    }
    pub const fn key_id(&self) -> CatalogDigest {
        self.key_id
    }
    pub const fn index_hash(&self) -> CatalogDigest {
        self.index_sha256
    }
    pub fn release_tag(&self) -> &str {
        &self.release_tag
    }
    pub fn release_commit(&self) -> &str {
        &self.release_commit
    }
    pub const fn sequence(&self) -> u64 {
        self.release_sequence
    }
    pub const fn offline(&self) -> bool {
        self.offline
    }
    pub const fn downgrade_confirmed(&self) -> bool {
        self.downgrade_confirmed
    }
}
