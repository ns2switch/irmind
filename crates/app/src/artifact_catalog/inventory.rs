use crate::{AppError, SignedEntry, sha256, sha256_stream};
use irmind_domain::{
    AuditEventKind, EvidenceHash, ParquetArtifactV3, SealInventoryV2, SealItemKind,
    SourceManifestV2,
};
use std::collections::BTreeMap;

/// Compact canonical inventory of metadata authenticated by the caller's
/// mandatory signature/chain verification. No original content is retained.
#[derive(Default)]
pub struct SealInventoryBuilder {
    items: BTreeMap<(SealItemKind, String), [u8; 32]>,
    has_mapped_artifacts: bool,
}
impl SealInventoryBuilder {
    pub fn accept(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        let bad = || AppError::InvalidChain(entry.seq);
        if entry.kind.is_retired_case_format() {
            return Err(AppError::Fixed(crate::FixedAppError::RetiredCaseFormat));
        }
        match entry.kind {
            AuditEventKind::SourceManifestV2 => {
                let source = SourceManifestV2::decode(&entry.payload).map_err(|_| bad())?;
                let payload = source.encode().map_err(|_| bad())?;
                self.insert(
                    SealItemKind::Source,
                    &source.source.source,
                    payload.as_bytes(),
                )?;
            }
            AuditEventKind::ParquetArtifactV3 => {
                let artifact = ParquetArtifactV3::decode(&entry.payload).map_err(|_| bad())?;
                self.insert(
                    SealItemKind::Artifact,
                    &artifact.core().path,
                    artifact.encode().map_err(|_| bad())?.as_bytes(),
                )?;
                self.has_mapped_artifacts = true;
            }
            _ => {}
        }
        Ok(())
    }
    fn insert(&mut self, kind: SealItemKind, key: &str, payload: &[u8]) -> Result<(), AppError> {
        let hash = SealInventoryV2::item_hash(kind, key, payload, sha256_stream);
        if self.items.insert((kind, key.into()), hash).is_some() {
            return Err(AppError::InvalidChain(0));
        }
        Ok(())
    }
    pub fn add_evidence(&mut self, hash: &str) -> Result<(), AppError> {
        EvidenceHash::parse(hash).map_err(|_| AppError::InvalidChain(0))?;
        self.insert(SealItemKind::Evidence, hash, hash.as_bytes())
    }
    pub const fn has_mapped_artifacts(&self) -> bool {
        self.has_mapped_artifacts
    }
    pub fn commitment(&self) -> Result<SealInventoryV2, AppError> {
        SealInventoryV2::from_ordered(
            self.items
                .iter()
                .map(|((kind, key), hash)| (*kind, key.as_str(), hash)),
            sha256_stream,
        )
        .map_err(|_| AppError::InvalidChain(0))
    }
    pub fn verify(&self, payload: &str) -> Result<(), AppError> {
        let signed = SealInventoryV2::decode(payload).map_err(|_| AppError::InvalidChain(0))?;
        if signed.count != self.items.len() as u64 || signed != self.commitment()? {
            return Err(AppError::InvalidChain(0));
        }
        Ok(())
    }
}

/// The production caller also verifies every signature. This independent
/// check keeps inventory verification bound to the exact ordered snapshot.
pub fn verify_seal_inventory_snapshot(
    entries: &[SignedEntry],
    legacy: &[String],
    payload: &str,
) -> Result<(), AppError> {
    if entries
        .iter()
        .any(|entry| entry.kind == AuditEventKind::ParquetArtifactV3)
    {
        let count = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.kind,
                    AuditEventKind::SourceManifestV2 | AuditEventKind::ParquetArtifactV3
                )
            })
            .count() as u64;
        let declared = SealInventoryV2::decode(payload).map_err(|_| AppError::InvalidChain(0))?;
        if count.checked_add(legacy.len() as u64) != Some(declared.count) {
            return Err(AppError::InvalidChain(0));
        }
    }
    let mut previous = None;
    for entry in entries {
        if sha256(&entry.canonical()) != entry.hash
            || previous.is_some_and(|p: &SignedEntry| {
                p.case_id != entry.case_id
                    || p.seq.checked_add(1) != Some(entry.seq)
                    || p.hash != entry.prev
            })
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        previous = Some(entry);
    }
    if super::seal_inventory(entries, legacy)?.join(",") != payload {
        return Err(AppError::InvalidChain(0));
    }
    Ok(())
}
