//! Replay each signed generation independently, preserving allocation order.
use super::{
    AppError, CancellationToken, CaseId, ParquetArtifact, ParquetStore, Path, SourceManifestV1,
    StreamingEventParser, TempWorkspace, invalid_source,
};
use std::collections::BTreeSet;

impl ParquetStore {
    pub(super) fn rebuild_generations(
        &self,
        case: &CaseId,
        root: &Path,
        sources: &[SourceManifestV1],
        artifacts: &[ParquetArtifact],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let workspace = TempWorkspace::new(&self.spool_dir(case)?)?;
        let mut fresh = Self::open(&workspace.path)?;
        let groups = generations(artifacts);
        let normalized = groups
            .iter()
            .map(|g| g.iter().map(replay_metadata).collect::<Result<Vec<_>, _>>())
            .collect::<Result<Vec<_>, _>>()?;
        let mut outputs = vec![Vec::new(); groups.len()];
        let mut checked = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut seed = Vec::new();
        // Replay first source appearances in signed order, including native
        // V2 files ingested between two explicit migrations.
        for artifact in artifacts.iter().filter(|a| a.source_hashes().len() == 1) {
            let group = groups
                .iter()
                .position(|g| {
                    g[0].same_generation(artifact)
                        && namespace(g[0].path()) == namespace(artifact.path())
                })
                .ok_or_else(invalid_source)?;
            let hash = &artifact.source_hashes()[0];
            let Some(source) = sources.iter().find(|s| &s.sha256 == hash) else {
                continue;
            };
            if !visited.insert((group, hash.clone())) {
                continue;
            }
            fresh.replay_mode(source, &normalized[group]);
            let actual = fresh.rebuild_source(
                (case, root, self.root.parent().ok_or_else(invalid_source)?),
                source,
                &normalized[group],
                &seed,
                parser,
                cancel,
            )?;
            seed.extend(actual.iter().cloned());
            outputs[group].extend(actual);
            checked.insert(hash.clone());
        }
        for (signed, rebuilt) in normalized.iter().zip(&outputs) {
            fresh.rebuild_bundles(case, signed, rebuilt, cancel)?;
        }
        Ok(checked.len())
    }

    fn rebuild_source(
        &self,
        location: (&CaseId, &Path, &Path),
        source: &SourceManifestV1,
        signed: &[ParquetArtifact],
        seed: &[ParquetArtifact],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifact>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (case, root, data_root) = location;
        let mut physical = source.clone();
        let legacy = source.source == format!("legacy/{}.json", source.sha256.as_str());
        let evidence_root = data_root.join("evidence");
        let root = if legacy {
            physical.source = source.sha256.as_str().into();
            evidence_root.as_path()
        } else {
            root
        };
        let routed = super::source_parser::SourceParser {
            inner: parser,
            logical: &source.source,
        };
        let paths = [physical.source.clone()];
        let prepared = self.replay_prepared(
            irmind_app::LocalBatchRequest {
                case_id: case,
                source_root: root,
                relative_paths: &paths,
                copy_original: false,
                parser: &routed,
                committed_artifacts: seed,
                limits: super::partitioning::replay_limits(&[seed, signed].concat())?,
            },
            &physical,
            signed,
            cancel,
        )?;
        if prepared.manifest.sha256 != source.sha256 || prepared.manifest.size != source.size {
            return Err(AppError::EvidenceMismatch(source.sha256.as_str().into()));
        }
        let mut actual = prepared.artifacts;
        let version = parser.identity_for_source(&source.source)?.version;
        let mut expected = signed
            .iter()
            .filter(|a| {
                a.source_hashes().len() == 1
                    && a.source_hashes()[0] == source.sha256
                    && a.parser_version() == version
            })
            .cloned()
            .collect::<Vec<_>>();
        actual.sort_by(|a, b| a.path().cmp(b.path()));
        expected.sort_by(|a, b| a.path().cmp(b.path()));
        if actual != expected {
            return Err(AppError::EvidenceMismatch(source.sha256.as_str().into()));
        }
        Ok(actual)
    }

    fn rebuild_bundles(
        &self,
        case: &CaseId,
        signed: &[ParquetArtifact],
        rebuilt: &[ParquetArtifact],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let available = rebuilt
            .iter()
            .flat_map(ParquetArtifact::source_hashes)
            .collect::<BTreeSet<_>>();
        for bundle in signed.iter().filter(|a| {
            a.source_hashes().len() > 1 && a.source_hashes().iter().all(|h| available.contains(h))
        }) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let inputs = rebuilt
                .iter()
                .filter(|a| {
                    a.compaction_key() == bundle.compaction_key()
                        && bundle.source_hashes().contains(&a.source_hashes()[0])
                })
                .cloned()
                .collect::<Vec<_>>();
            if self.compact_signed_sources(case, &inputs, cancel)? != *bundle {
                return Err(AppError::EvidenceMismatch(bundle.sha256().as_str().into()));
            }
        }
        Ok(())
    }
}

fn generations(artifacts: &[ParquetArtifact]) -> Vec<Vec<ParquetArtifact>> {
    let mut groups: Vec<Vec<ParquetArtifact>> = Vec::new();
    for artifact in artifacts {
        if let Some(group) = groups.iter_mut().find(|g| {
            g[0].same_generation(artifact) && namespace(g[0].path()) == namespace(artifact.path())
        }) {
            group.push(artifact.clone());
        } else {
            groups.push(vec![artifact.clone()]);
        }
    }
    groups
}

fn namespace(path: &str) -> Option<&str> {
    path.split('/').find(|s| s.starts_with("migration-"))
}

fn replay_metadata(artifact: &ParquetArtifact) -> Result<ParquetArtifact, AppError> {
    let mut out = artifact.clone();
    if let ParquetArtifact::V2(value) = &mut out {
        if value.superseded_hashes.is_empty() {
            return Ok(out);
        }
        let marker = namespace(&value.path)
            .ok_or_else(invalid_source)?
            .to_owned();
        if marker.len() != 74
            || !marker[10..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid_source());
        }
        value.path = value
            .path
            .split('/')
            .filter(|s| *s != marker)
            .collect::<Vec<_>>()
            .join("/");
        value.superseded_hashes.clear();
    }
    Ok(out)
}
