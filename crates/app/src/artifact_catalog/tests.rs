use super::*;
use irmind_domain::{
    Actor, AuditEventKind, EvidenceHash, ParserSelectionMode, SourceManifestV1, SourceManifestV2,
};
fn entry(kind: AuditEventKind, payload: String) -> SignedEntry {
    SignedEntry {
        seq: 1,
        case_id: "11111111-1111-1111-1111-111111111111".into(),
        at: 0,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind,
        payload,
        evidence: None,
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: Vec::new(),
    }
}
fn hash(digit: &str) -> EvidenceHash {
    EvidenceHash::parse(&digit.repeat(64)).unwrap()
}
fn source(name: &str, hash: EvidenceHash) -> SourceManifestV1 {
    SourceManifestV1 {
        source: name.into(),
        sha256: hash,
        size: 1,
        modified_unix_seconds: None,
        version: None,
        provider_checksum: None,
        copied: false,
    }
}
mod scale;

mod mapped;
