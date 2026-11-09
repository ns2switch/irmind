//! Exact decoding/mapping reconstruction is distinct from file authentication.
mod source;
use super::super::{
    AppError, CancellationToken, CaseId, ParquetArtifact, ParquetStore, Path, TempWorkspace,
    invalid_source,
};
use irmind_app::{LargeCaseStore, SignedEntry};
use irmind_domain::{
    ArtifactDerivationV1, AuditEventKind, EvidenceHash, MappingProfileRecordV1, MappingProfileV1,
    ParquetArtifactV3, SourceManifestV2, SourceRecordSetV1,
};
use std::collections::BTreeMap;

#[derive(Default)]
struct Inputs {
    sources: BTreeMap<EvidenceHash, SourceManifestV2>,
    sets: BTreeMap<EvidenceHash, SourceRecordSetV1>,
    profiles: BTreeMap<EvidenceHash, MappingProfileV1>,
    runs: BTreeMap<EvidenceHash, irmind_domain::MappingRunV1>,
}
impl Inputs {
    fn from_entries(entries: &[SignedEntry]) -> Result<Self, AppError> {
        let mut value = Self::default();
        for entry in entries {
            let bad = || AppError::InvalidChain(entry.seq);
            match entry.kind {
                AuditEventKind::SourceManifestV2 => {
                    let source = SourceManifestV2::decode(&entry.payload).map_err(|_| bad())?;
                    value.sources.insert(source.source.sha256.clone(), source);
                }
                AuditEventKind::SourceRecordSetV1 => {
                    let input = SourceRecordSetV1::decode(&entry.payload).map_err(|_| bad())?;
                    value
                        .sets
                        .insert(input.identity().map_err(|_| bad())?, input);
                }
                AuditEventKind::MappingProfileV1 => {
                    if let MappingProfileRecordV1::Profile(profile) =
                        MappingProfileRecordV1::decode(&entry.payload).map_err(|_| bad())?
                    {
                        value
                            .profiles
                            .insert(profile.identity().map_err(|_| bad())?, profile);
                    }
                }
                AuditEventKind::MappingRunV1 => {
                    let run =
                        irmind_domain::MappingRunV1::decode(&entry.payload).map_err(|_| bad())?;
                    value.runs.insert(run.profile().clone(), run);
                }
                _ => {}
            }
        }
        Ok(value)
    }
}
impl ParquetStore {
    pub(crate) fn rebuild_mapped_history(
        &self,
        case: &CaseId,
        root: &Path,
        entries: &[SignedEntry],
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let inventory = irmind_app::artifact_catalog(entries)?;
        let inputs = Inputs::from_entries(entries)?;
        let workspace = TempWorkspace::new(&self.spool_dir(case)?)?;
        let mut rebuilt = BTreeMap::new();
        let mut seed = Vec::new();
        let mut count = 0;
        for artifact in &inventory.all {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let ParquetArtifact::V3(mapped) = artifact else {
                seed.push(artifact.clone());
                continue;
            };
            self.verify_artifact(case, artifact, cancel)?;
            if rebuilt.contains_key(artifact.path()) {
                continue;
            }
            match mapped.pipeline().derivation() {
                ArtifactDerivationV1::Mapped => {
                    let generated = self.rebuild_mapping_source(
                        (case, root, &workspace.path),
                        mapped,
                        &inputs,
                        &seed,
                        cancel,
                    )?;
                    for actual in generated {
                        if !inventory.all.contains(&ParquetArtifact::V3(actual.clone())) {
                            return Err(AppError::EvidenceMismatch(
                                actual.core().sha256.as_str().into(),
                            ));
                        }
                        seed.push(ParquetArtifact::V3(actual.clone()));
                        rebuilt.insert(actual.core().path.clone(), actual);
                    }
                    count += rebuilt_sources(mapped, &inputs)?;
                }
                ArtifactDerivationV1::Layout { parents } => {
                    let parents = parents
                        .iter()
                        .map(|p| {
                            rebuilt
                                .get(p.path())
                                .cloned()
                                .map(ParquetArtifact::V3)
                                .ok_or_else(invalid_source)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let fresh = Self::open(&workspace.path)?;
                    let actual = fresh.compact_artifacts(case, &parents, cancel)?;
                    if actual != *artifact {
                        return Err(AppError::EvidenceMismatch(
                            artifact.sha256().as_str().into(),
                        ));
                    }
                    seed.push(actual);
                    rebuilt.insert(mapped.core().path.clone(), mapped.clone());
                }
            }
        }
        let expected = inventory
            .all
            .iter()
            .filter(|a| matches!(a, ParquetArtifact::V3(_)))
            .count();
        if rebuilt.len() != expected {
            return Err(invalid_source());
        }
        Ok(count)
    }
}

fn rebuilt_sources(artifact: &ParquetArtifactV3, inputs: &Inputs) -> Result<usize, AppError> {
    if artifact.core().builder_version != irmind_domain::COMMON_EVENT_DIRECT_BUILDER {
        return Ok(1);
    }
    let binding = artifact.bindings().first().ok_or_else(invalid_source)?;
    Ok(inputs
        .profiles
        .get(binding.profile())
        .ok_or_else(invalid_source)?
        .inputs()
        .len())
}
