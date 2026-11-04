use crate::{
    AppError, CancellationToken, CaseId, PartitionLimits, SignedEntry, StreamingEventParser,
};
use irmind_domain::{ParquetArtifactV2, ParquetMigrationV1};
use std::path::Path;

pub struct ArtifactMigrationRequest<'a> {
    pub case_id: &'a CaseId,
    pub source_root: Option<&'a Path>,
    pub signed_entries: &'a [SignedEntry],
    pub parser: &'a dyn StreamingEventParser,
    pub limits: PartitionLimits,
}

pub trait PreparedArtifactMigration: Send {
    fn artifacts(&self) -> &[ParquetArtifactV2];
    fn record(&self) -> &ParquetMigrationV1;
    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError>;
    fn retain_committed(&mut self);
}

pub struct ArtifactCatalog {
    pub all: Vec<irmind_domain::ParquetArtifact>,
    pub active: Vec<irmind_domain::ParquetArtifact>,
}

pub struct ArtifactCatalogBuilder {
    lineage: irmind_domain::ArtifactLineage,
    names: std::collections::BTreeSet<String>,
}
impl Default for ArtifactCatalogBuilder {
    fn default() -> Self {
        Self {
            lineage: irmind_domain::ArtifactLineage::new(crate::sha256_stream),
            names: std::collections::BTreeSet::new(),
        }
    }
}
impl ArtifactCatalogBuilder {
    pub fn accept(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        use irmind_domain::{
            Actor, AuditEventKind, EvidenceHash, ParquetArtifact, SourceManifestV1,
            SourceManifestV2,
        };
        let invalid = || AppError::InvalidChain(entry.seq);
        if self.lineage.has_pending()
            && !matches!(
                entry.kind,
                AuditEventKind::ParquetArtifactV2 | AuditEventKind::ParquetArtifactsMigrated
            )
        {
            return Err(invalid());
        }
        match entry.kind {
            AuditEventKind::EvidenceIngested | AuditEventKind::GraphIndexed => {
                let hash = EvidenceHash::parse(entry.evidence.as_deref().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                self.lineage
                    .source(hash, "parser-json", "json-stream-v2", false)
                    .map_err(|_| invalid())?;
            }
            AuditEventKind::SourceManifestV1 | AuditEventKind::SourceManifestV2 => {
                if entry.evidence.is_some() {
                    return Err(invalid());
                }
                let source = SourceManifestV1::decode_signed(entry.kind, &entry.payload)
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                if !self.names.insert(source.source) {
                    return Err(invalid());
                }
                let (id, version, manifest) = if entry.kind == AuditEventKind::SourceManifestV2 {
                    let v = SourceManifestV2::decode(&entry.payload).map_err(|_| invalid())?;
                    (v.parser_id, v.parser_version, true)
                } else {
                    ("parser-json".into(), "json-stream-v2".into(), false)
                };
                self.lineage
                    .source(source.sha256, &id, &version, manifest)
                    .map_err(|_| invalid())?;
            }
            AuditEventKind::ParquetArtifactV1 | AuditEventKind::ParquetArtifactV2 => {
                if entry.evidence.is_some() {
                    return Err(invalid());
                }
                self.lineage
                    .artifact(
                        ParquetArtifact::decode(entry.kind, &entry.payload)
                            .map_err(|_| invalid())?,
                    )
                    .map_err(|_| invalid())?;
            }
            AuditEventKind::ParquetArtifactsMigrated => {
                if entry.actor != Actor::Analyst || entry.evidence.is_some() {
                    return Err(invalid());
                }
                self.lineage
                    .migrate(&ParquetMigrationV1::decode(&entry.payload).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
            }
            _ => {}
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), AppError> {
        self.lineage
            .all()
            .map(|_| ())
            .map_err(|_| AppError::InvalidChain(0))
    }
    pub fn finish(&self) -> Result<ArtifactCatalog, AppError> {
        Ok(ArtifactCatalog {
            all: self
                .lineage
                .all()
                .map_err(|_| AppError::InvalidChain(0))?
                .to_vec(),
            active: self
                .lineage
                .active()
                .map_err(|_| AppError::InvalidChain(0))?,
        })
    }
}

pub fn artifact_catalog(entries: &[SignedEntry]) -> Result<ArtifactCatalog, AppError> {
    let mut catalog = ArtifactCatalogBuilder::default();
    for entry in entries {
        catalog.accept(entry)?;
    }
    catalog.finish()
}

pub fn seal_inventory(entries: &[SignedEntry], legacy: &[String]) -> Result<Vec<String>, AppError> {
    use irmind_domain::{AuditEventKind, SourceManifestV1};
    if !entries.iter().any(|e| {
        matches!(
            e.kind,
            AuditEventKind::ParquetArtifactV2 | AuditEventKind::ParquetArtifactsMigrated
        )
    }) {
        return Ok(legacy.to_vec());
    }
    let catalog = artifact_catalog(entries)?;
    let mut hashes = legacy
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for entry in entries {
        if let Some(source) = SourceManifestV1::decode_signed(entry.kind, &entry.payload)
            .map_err(|_| AppError::InvalidChain(entry.seq))?
        {
            hashes.insert(source.sha256.as_str().into());
        }
    }
    hashes.extend(catalog.all.iter().map(|a| a.sha256().as_str().to_owned()));
    Ok(hashes.into_iter().collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
