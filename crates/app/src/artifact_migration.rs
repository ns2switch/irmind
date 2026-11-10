mod inventory;
mod mapped;
use crate::{
    AppError, CancellationToken, CaseId, PartitionLimits, SignedEntry, StreamingEventParser,
};
pub use inventory::{SealInventoryBuilder, verify_seal_inventory_snapshot};
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
    mapped: irmind_domain::MappingLineageV1,
    names: std::collections::BTreeSet<String>,
    artifact_order: Vec<String>,
}
impl Default for ArtifactCatalogBuilder {
    fn default() -> Self {
        Self {
            mapped: irmind_domain::MappingLineageV1::default(),
            names: std::collections::BTreeSet::new(),
            artifact_order: Vec::new(),
        }
    }
}
impl ArtifactCatalogBuilder {
    pub fn accept(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        use irmind_domain::{AuditEventKind, SourceManifestV2};
        let invalid = || AppError::InvalidChain(entry.seq);
        if entry.kind.is_retired_case_format() {
            return Err(AppError::Fixed(crate::FixedAppError::RetiredCaseFormat));
        }
        if self.mapped.has_pending()
            && !matches!(
                entry.kind,
                AuditEventKind::ParquetArtifactV3
                    | AuditEventKind::MappingRunV1
                    | AuditEventKind::ParquetLayoutV1
            )
        {
            return Err(invalid());
        }
        if entry.kind.is_mapped_custody() {
            return self.accept_mapped(entry);
        }
        if entry.kind == AuditEventKind::SourceManifestV2 {
            if entry.evidence.is_some() {
                return Err(invalid());
            }
            let source = SourceManifestV2::decode(&entry.payload).map_err(|_| invalid())?;
            if !self.names.insert(source.source.source.clone()) {
                return Err(invalid());
            }
            self.mapped.source(source).map_err(|_| invalid())?;
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), AppError> {
        self.finish().map(|_| ())
    }
    pub fn finish(&self) -> Result<ArtifactCatalog, AppError> {
        use irmind_domain::ParquetArtifact;
        let bad = || AppError::InvalidChain(0);
        let mapped = self.mapped.all().map_err(|_| bad())?;
        let mut by_path = std::collections::BTreeMap::new();
        for artifact in mapped.into_iter().cloned().map(ParquetArtifact::V3) {
            if by_path
                .insert(artifact.path().to_owned(), artifact)
                .is_some()
            {
                return Err(bad());
            }
        }
        let active_paths = self
            .mapped
            .active()
            .map_err(|_| bad())?
            .iter()
            .map(|a| a.core().path.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut all = Vec::with_capacity(by_path.len());
        for path in &self.artifact_order {
            all.push(by_path.remove(path).ok_or_else(bad)?);
        }
        if !by_path.is_empty() {
            return Err(bad());
        }
        let active = all
            .iter()
            .filter(|a| active_paths.contains(a.path()))
            .cloned()
            .collect();
        Ok(ArtifactCatalog { all, active })
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
    use irmind_domain::AuditEventKind;
    if !entries.iter().any(|e| {
        matches!(
            e.kind,
            AuditEventKind::ParquetArtifactV2
                | AuditEventKind::ParquetArtifactV3
                | AuditEventKind::ParquetArtifactsMigrated
        )
    }) {
        return Ok(legacy.to_vec());
    }
    let mut catalog = ArtifactCatalogBuilder::default();
    let mut inventory = SealInventoryBuilder::default();
    for entry in entries {
        catalog.accept(entry)?;
        inventory.accept(entry)?;
    }
    catalog.validate()?;
    for hash in legacy {
        inventory.add_evidence(hash)?;
    }
    let payload = inventory
        .commitment()?
        .encode()
        .map_err(|_| AppError::InvalidChain(0))?;
    Ok(vec![payload])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
