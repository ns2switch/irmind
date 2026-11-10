//! Shared metadata commitment types for seals and mapping receipts.
use super::EvidenceHash;

pub type ByteStream<'a> = dyn FnMut(&mut dyn FnMut(&[u8])) + 'a;
pub type DigestStream = fn(&mut ByteStream<'_>) -> [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetCommitment {
    pub count: u64,
    pub sha256: EvidenceHash,
}
