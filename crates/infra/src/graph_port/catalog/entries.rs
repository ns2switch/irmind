use super::{AppError, AuditEventKind, EvidenceHash, ParquetArtifact};
use irmind_domain::{SourceManifestV1, SourceManifestV2};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct SignedSources {
    pub(super) source_names: BTreeMap<String, String>,
    sources: BTreeSet<EvidenceHash>,
    pub(super) new_source_hashes: BTreeSet<EvidenceHash>,
    pub(super) legacy_hashes: BTreeSet<EvidenceHash>,
    pub(super) artifacts: Vec<ParquetArtifact>,
    parser_choices: BTreeMap<EvidenceHash, BTreeSet<(String, String)>>,
}
impl SignedSources {
    pub(super) fn accept(&mut self, entry: &irmind_app::SignedEntry) -> Result<(), AppError> {
        match entry.kind {
            AuditEventKind::EvidenceIngested | AuditEventKind::GraphIndexed => {
                let hash = entry
                    .evidence
                    .as_deref()
                    .ok_or(AppError::InvalidChain(entry.seq))?;
                let hash =
                    EvidenceHash::parse(hash).map_err(|_| AppError::InvalidChain(entry.seq))?;
                if entry.kind == AuditEventKind::GraphIndexed {
                    self.legacy_hashes.insert(hash.clone());
                }
                self.sources.insert(hash);
            }
            AuditEventKind::SourceManifestV1 | AuditEventKind::SourceManifestV2 => {
                self.source(entry)?;
            }
            AuditEventKind::ParquetArtifactV1 | AuditEventKind::ParquetArtifactV2 => {
                self.artifact(entry)?;
            }
            _ => {}
        }
        Ok(())
    }
    fn source(&mut self, entry: &irmind_app::SignedEntry) -> Result<(), AppError> {
        if entry.evidence.is_some() {
            return Err(AppError::InvalidChain(entry.seq));
        }
        let source = SourceManifestV1::decode_signed(entry.kind, &entry.payload)
            .map_err(|_| AppError::InvalidChain(entry.seq))?
            .ok_or(AppError::InvalidChain(entry.seq))?;
        if entry.kind == AuditEventKind::SourceManifestV2 {
            let selection = SourceManifestV2::decode(&entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            let choice = (selection.parser_id, selection.parser_version);
            self.parser_choices
                .entry(source.sha256.clone())
                .or_default()
                .insert(choice);
        }
        self.source_names
            .entry(source.sha256.as_str().into())
            .and_modify(|old| {
                if source.source < *old {
                    old.clone_from(&source.source);
                }
            })
            .or_insert_with(|| source.source.clone());
        self.new_source_hashes.insert(source.sha256.clone());
        self.sources.insert(source.sha256);
        Ok(())
    }
    fn artifact(&mut self, entry: &irmind_app::SignedEntry) -> Result<(), AppError> {
        let artifact = ParquetArtifact::decode(entry.kind, &entry.payload)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
        if entry.evidence.is_some() {
            return Err(AppError::InvalidChain(entry.seq));
        }
        self.artifacts.push(artifact);
        Ok(())
    }
}
