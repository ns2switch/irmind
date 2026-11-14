use super::{
    CatalogDigest, CatalogError, CatalogIndexBytes, CatalogIndexVerifier, CatalogProofId,
    CatalogProofRequirement, VerifiedCatalogIndex,
};
use crate::AppError;
use serde::{Deserialize, Serialize};

const CHUNK: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    proof_sha256: CatalogDigest,
    index_sha256: CatalogDigest,
    key_id: CatalogDigest,
    signature: String,
    index_bytes: u64,
    chunks: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    proof_sha256: CatalogDigest,
    ordinal: u64,
    bytes_hex: String,
}
pub fn catalog_proof_descriptor(index: &VerifiedCatalogIndex) -> Result<Vec<u8>, CatalogError> {
    serde_json::to_vec(&Descriptor {
        proof_sha256: index.proof_id().digest(),
        index_sha256: index.index_hash(),
        key_id: index.index().key_id(),
        signature: crate::hex(index.raw().signature()),
        index_bytes: index.raw().index().len() as u64,
        chunks: index.raw().index().len().div_ceil(CHUNK) as u64,
    })
    .map_err(|_| CatalogError::InvalidData)
}
pub fn catalog_proof_chunk(
    index: &VerifiedCatalogIndex,
    ordinal: u64,
) -> Result<Vec<u8>, CatalogError> {
    let start = usize::try_from(ordinal)
        .ok()
        .and_then(|n| n.checked_mul(CHUNK))
        .ok_or(CatalogError::InvalidData)?;
    let bytes = index
        .raw()
        .index()
        .get(start..)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(CatalogError::InvalidData)?;
    serde_json::to_vec(&Chunk {
        proof_sha256: index.proof_id().digest(),
        ordinal,
        bytes_hex: crate::hex(&bytes[..bytes.len().min(CHUNK)]),
    })
    .map_err(|_| CatalogError::InvalidData)
}

/// Bounded, ordered proof reassembly. Any failed chunk poisons this reader.
pub struct CatalogProofReader {
    descriptor: Descriptor,
    signature: [u8; 64],
    index: Vec<u8>,
    next: u64,
    failed: bool,
}
impl CatalogProofReader {
    pub fn new(bytes: &[u8], expected: CatalogProofId) -> Result<Self, CatalogError> {
        if bytes.len() > 4096 {
            return Err(CatalogError::InvalidData);
        }
        super::limits::check(bytes)?;
        let descriptor: Descriptor =
            serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidData)?;
        if descriptor.index_bytes == 0
            || descriptor.index_bytes > 1024 * 1024
            || descriptor.chunks != descriptor.index_bytes.div_ceil(CHUNK as u64)
            || descriptor.proof_sha256 != expected.digest()
            || serde_json::to_vec(&descriptor).map_err(|_| CatalogError::InvalidData)? != bytes
        {
            return Err(CatalogError::InvalidData);
        }
        let signature =
            hex::decode(&descriptor.signature).map_err(|_| CatalogError::InvalidData)?;
        if signature.len() != 64 || crate::hex(&signature) != descriptor.signature {
            return Err(CatalogError::InvalidData);
        }
        Ok(Self {
            descriptor,
            signature: signature
                .try_into()
                .map_err(|_| CatalogError::InvalidData)?,
            index: Vec::new(),
            next: 0,
            failed: false,
        })
    }
    pub const fn index_bytes(&self) -> u64 {
        self.descriptor.index_bytes
    }
    pub const fn chunk_count(&self) -> u64 {
        self.descriptor.chunks
    }
    pub fn accept(&mut self, bytes: &[u8]) -> Result<(), CatalogError> {
        if self.failed {
            return Err(CatalogError::InvalidData);
        }
        let result = self.accept_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn accept_inner(&mut self, bytes: &[u8]) -> Result<(), CatalogError> {
        if bytes.len() > 1024 * 1024 || self.next >= self.descriptor.chunks {
            return Err(CatalogError::InvalidData);
        }
        super::limits::check(bytes)?;
        let chunk: Chunk = serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidData)?;
        let remaining = usize::try_from(self.descriptor.index_bytes)
            .map_err(|_| CatalogError::InvalidData)?
            .checked_sub(self.index.len())
            .ok_or(CatalogError::InvalidData)?;
        if chunk.proof_sha256 != self.descriptor.proof_sha256
            || chunk.ordinal != self.next
            || chunk.bytes_hex.len() != remaining.min(CHUNK) * 2
            || serde_json::to_vec(&chunk).map_err(|_| CatalogError::InvalidData)? != bytes
        {
            return Err(CatalogError::InvalidData);
        }
        let decoded = hex::decode(&chunk.bytes_hex).map_err(|_| CatalogError::InvalidData)?;
        if crate::hex(&decoded) != chunk.bytes_hex {
            return Err(CatalogError::InvalidData);
        }
        self.index.extend(decoded);
        self.next += 1;
        Ok(())
    }
    pub fn finish(
        self,
        expected: &CatalogProofRequirement,
        verifier: &dyn CatalogIndexVerifier,
    ) -> Result<VerifiedCatalogIndex, AppError> {
        if self.failed
            || self.next != self.descriptor.chunks
            || self.index.len() as u64 != self.descriptor.index_bytes
            || &crate::sha256(&self.index) != self.descriptor.index_sha256.as_bytes()
        {
            return Err(CatalogError::InvalidData.into());
        }
        let raw = CatalogIndexBytes::new(self.index, &self.signature)?;
        if raw.proof_id() != expected.proof() {
            return Err(CatalogError::InvalidData.into());
        }
        let index = verifier.verify(&raw, expected.release())?;
        if index.index().key_id() != self.descriptor.key_id {
            return Err(CatalogError::InvalidData.into());
        }
        Ok(index)
    }
}
