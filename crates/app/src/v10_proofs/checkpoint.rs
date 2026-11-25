//! Resolve coordinates using the authenticated prefix, including evidence lineage.
use super::{
    CaseCheckpointV1, V10ArtifactReference, V10AuditReference, V10RowReference, V10SourceReference,
};
use crate::{AppError, SignedEntry, artifact_catalog, sha256};
use irmind_domain::{
    Actor, ArtifactSchemaV2, AuditEventKind, EvidenceHash, ParquetArtifact, SourceManifestV2,
    SourceRecordSetV1,
};
use std::collections::{BTreeMap, BTreeSet};

pub struct V10CheckpointView<'a> {
    entries: &'a [SignedEntry],
    active_paths: BTreeSet<String>,
    source_sets: BTreeMap<String, SourceRecordSetV1>,
}

impl<'a> V10CheckpointView<'a> {
    /// The caller must authenticate the ledger and its signing actors before
    /// trusting the prefix. The view checks identity and scope, and the caller
    /// authenticates the referenced Parquet bytes and physical row.
    pub fn resolve(
        entries: &'a [SignedEntry],
        checkpoint: &CaseCheckpointV1,
    ) -> Result<Self, AppError> {
        let invalid = || AppError::InvalidChain(checkpoint.sequence);
        let length = entries.partition_point(|entry| entry.seq <= checkpoint.sequence);
        let entries = &entries[..length];
        let edge = entries.last().ok_or_else(invalid)?;
        if edge.seq != checkpoint.sequence
            || edge.hash != checkpoint.entry_hash
            || edge.case_id != checkpoint.case_id.as_str()
        {
            return Err(invalid());
        }
        let catalog = artifact_catalog(entries)?;
        let active_paths = catalog
            .active
            .iter()
            .map(|artifact| artifact.path().to_owned())
            .collect();
        let mut source_sets = BTreeMap::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceRecordSetV1)
        {
            let set = SourceRecordSetV1::decode(&entry.payload).map_err(|_| invalid())?;
            let identity = set.identity().map_err(|_| invalid())?;
            if source_sets
                .insert(identity.as_str().to_owned(), set)
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            entries,
            active_paths,
            source_sets,
        })
    }

    pub fn entry(
        &self,
        reference: V10AuditReference,
        kind: AuditEventKind,
    ) -> Result<&SignedEntry, AppError> {
        self.entries
            .binary_search_by_key(&reference.sequence, |entry| entry.seq)
            .ok()
            .and_then(|position| self.entries.get(position))
            .filter(|entry| entry.hash == reference.entry_sha256 && entry.kind == kind)
            .ok_or(AppError::InvalidChain(reference.sequence))
    }

    pub fn entries(&self) -> &[SignedEntry] {
        self.entries
    }

    /// Use the existing seal inventory commitment on just the active artifact
    /// entries. Compacted parents remain in the case seal and outside this scan.
    pub fn active_artifact_inventory(&self) -> Result<[u8; 32], AppError> {
        let mut inventory = crate::SealInventoryBuilder::default();
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::ParquetArtifactV3)
        {
            let artifact = ParquetArtifact::decode(entry.kind, &entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            if self.active_paths.contains(artifact.path()) {
                inventory.accept(entry)?;
            }
        }
        let inventory = inventory.commitment()?;
        let mut bytes = [0; 32];
        hex::decode_to_slice(inventory.sha256.as_str(), &mut bytes)
            .map_err(|_| AppError::InvalidChain(0))?;
        Ok(bytes)
    }

    pub fn confirmed_finding(
        &self,
        confirmation: V10AuditReference,
        id: &str,
    ) -> Result<(), AppError> {
        let entry = self.entry(confirmation, AuditEventKind::FindingConfirmed)?;
        if entry.actor != Actor::Analyst || entry.payload != id || entry.evidence.is_some() {
            return Err(AppError::InvalidChain(confirmation.sequence));
        }
        Ok(())
    }

    pub fn source(&self, reference: V10SourceReference) -> Result<SourceManifestV2, AppError> {
        let entry = self.entry(reference.manifest, AuditEventKind::SourceManifestV2)?;
        let invalid = || AppError::InvalidChain(entry.seq);
        let manifest = SourceManifestV2::decode(&entry.payload).map_err(|_| invalid())?;
        if manifest.source.sha256 != EvidenceHash::from_bytes(reference.evidence_sha256) {
            return Err(invalid());
        }
        Ok(manifest)
    }

    pub(super) fn records_for_source(
        &self,
        reference: V10SourceReference,
    ) -> Result<u64, AppError> {
        let manifest = self.source(reference)?;
        self.source_sets
            .values()
            .filter(|set| set.validate_manifest(&manifest).is_ok())
            .map(irmind_domain::SourceRecordSetV1::records)
            .max()
            .ok_or(AppError::InvalidChain(reference.manifest.sequence))
    }

    pub fn artifact(
        &self,
        source: V10SourceReference,
        reference: V10ArtifactReference,
    ) -> Result<ParquetArtifact, AppError> {
        let manifest = self.source(source)?;
        let entry = self.entry(reference.entry, AuditEventKind::ParquetArtifactV3)?;
        let invalid = || AppError::InvalidChain(entry.seq);
        let artifact =
            ParquetArtifact::decode(entry.kind, &entry.payload).map_err(|_| invalid())?;
        let ParquetArtifact::V3(value) = &artifact;
        if *artifact.sha256() != EvidenceHash::from_bytes(reference.artifact_sha256)
            || !self.active_paths.contains(artifact.path())
            || !value.pipeline().bindings().iter().any(|binding| {
                binding.input().source() == &manifest.source.sha256
                    && self
                        .source_sets
                        .get(binding.input().set().as_str())
                        .is_some_and(|set| set.validate_manifest(&manifest).is_ok())
            })
        {
            return Err(invalid());
        }
        Ok(artifact)
    }

    pub fn row_artifact(&self, row: V10RowReference) -> Result<ParquetArtifact, AppError> {
        let artifact = self.artifact(row.source, row.artifact)?;
        let ParquetArtifact::V3(value) = &artifact;
        if value.core().schema != ArtifactSchemaV2::CommonEvents
            || row.physical_row >= value.pipeline().rows()
        {
            return Err(AppError::InvalidChain(row.artifact.entry.sequence));
        }
        Ok(artifact)
    }
}

/// Compare the identity columns decoded from a hash-authenticated physical row.
pub fn verify_v10_row_identity(
    reference: V10RowReference,
    source_hash: &str,
    record: u64,
) -> Result<(), AppError> {
    if source_hash != EvidenceHash::from_bytes(reference.source.evidence_sha256).as_str()
        || record != reference.record
    {
        return Err(AppError::InvalidChain(reference.artifact.entry.sequence));
    }
    Ok(())
}

/// Read the identity of a typed reviewed response, never admitting free text
/// as a citation or giving it the analyst's authority.
pub fn lookup_v10_model_draft(entries: &[SignedEntry], digest: &[u8; 32]) -> Option<usize> {
    entries.iter().position(|entry| {
        entry.kind == AuditEventKind::ModelReply
            && &entry.hash == digest
            && matches!(entry.actor, Actor::Agent(_))
            && sha256(&entry.canonical()) == entry.hash
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wrong_record_in_the_same_artifact_is_rejected() {
        let bytes = super::super::report_objects::tests::object("report_citations");
        let cites = super::super::ReportCitationsV1::decode(&bytes).unwrap();
        let super::super::V10Citation::Row(reference) = cites.0[0].citations[0] else {
            unreachable!();
        };
        let evidence = EvidenceHash::from_bytes(reference.source.evidence_sha256);
        verify_v10_row_identity(reference, evidence.as_str(), 9).unwrap();
        assert!(verify_v10_row_identity(reference, evidence.as_str(), 8).is_err());
        assert!(verify_v10_row_identity(reference, &"0".repeat(64), 9).is_err());

        let bytes = super::super::report_objects::tests::object("reject_unresolved_row");
        let modified = super::super::ReportCitationsV1::decode(&bytes).unwrap();
        let super::super::V10Citation::Row(moved) = modified.0[0].citations[0] else {
            unreachable!();
        };
        assert_eq!(moved.physical_row, reference.physical_row + 1);
        assert!(verify_v10_row_identity(moved, evidence.as_str(), 10).is_err());
    }
}
