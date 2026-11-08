//! Layout receipts activate replacements without retiring any parent files.
use super::{AppError, BTreeMap, CancellationToken, CaseId, LargeCaseUseCases, ParquetArtifact};
use crate::AuditOrigin;
use irmind_domain::{AuditEventKind, EvidenceHash, ParquetArtifactV3, ParquetLayoutV1};

impl LargeCaseUseCases<'_, '_> {
    pub(super) fn compact_mapped(
        &self,
        id: &CaseId,
        known: &BTreeMap<String, ParquetArtifact>,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let mut groups = BTreeMap::<Vec<u8>, Vec<ParquetArtifactV3>>::new();
        for artifact in known.values() {
            if let ParquetArtifact::V3(mapped) = artifact {
                groups
                    .entry(artifact.compaction_key())
                    .or_default()
                    .push(mapped.clone());
            }
        }
        let mut compacted = 0;
        for group in groups.values() {
            for parents in bounded_groups(group)? {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let inputs = parents
                    .iter()
                    .cloned()
                    .map(ParquetArtifact::V3)
                    .collect::<Vec<_>>();
                let bundle = self.store.compact_artifacts(id, &inputs, cancel)?;
                self.store.verify_artifact(id, &bundle, cancel)?;
                let ParquetArtifact::V3(child) = &bundle else {
                    return Err(super::invalid_manifest());
                };
                let receipt = ParquetLayoutV1::between(&parents, child)
                    .map_err(|_| super::invalid_manifest())?;
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                self.engine.audit_batch(
                    id,
                    &[
                        (
                            AuditOrigin::System,
                            AuditEventKind::ParquetArtifactV3,
                            child.encode().map_err(|_| super::invalid_manifest())?,
                        ),
                        (
                            AuditOrigin::System,
                            AuditEventKind::ParquetLayoutV1,
                            receipt.encode().map_err(|_| super::invalid_manifest())?,
                        ),
                    ],
                )?;
                compacted += 1;
            }
        }
        Ok(compacted)
    }
}

/// Envelope size is bounded independently of the physical file size. Greedily
/// preflight the canonical metadata before asking an adapter to write anything.
fn bounded_groups(group: &[ParquetArtifactV3]) -> Result<Vec<Vec<ParquetArtifactV3>>, AppError> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    for parent in group {
        parent.validate().map_err(|_| super::invalid_manifest())?;
        current.push(parent.clone());
        if current.len() > 1
            && ParquetLayoutV1::replacement(&current, 0, EvidenceHash::from_bytes([0; 32])).is_err()
        {
            let last = current.pop().ok_or_else(super::invalid_manifest)?;
            if current.len() >= 2 {
                chunks.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            current.push(last);
        }
    }
    if current.len() >= 2 {
        chunks.push(current);
    }
    Ok(chunks)
}
