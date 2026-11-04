mod inputs;
mod prepared;
mod recovery;
use super::source_parser;

use super::{
    AppError, CancellationToken, CaseId, GraphRecord, LargeCaseStore, ParquetArtifact,
    ParquetStore, Path, PathBuf, SourceManifestV1, StreamingEventParser, TempWorkspace,
    invalid_source, parse_hash, storage,
};
use irmind_app::{ArtifactMigrationRequest, LocalBatchRequest, PreparedArtifactMigration};
use irmind_domain::{EvidenceHash, ParquetArtifactV2, ParquetMigrationV1};
use std::collections::{BTreeMap, BTreeSet};

type ParserChoices = BTreeMap<EvidenceHash, (String, String)>;
type ConvertedSources = (Vec<ParquetArtifactV2>, ParserChoices);

impl ParquetStore {
    pub(super) fn prepare_migration(
        &self,
        request: &ArtifactMigrationRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PreparedArtifactMigration>, AppError> {
        request.limits.validate()?;
        let catalog = irmind_app::artifact_catalog(request.signed_entries)?;
        let old = eligible(&catalog.active)?;
        let inputs = inputs::resolve(self, request, &old, cancel)?;
        // Verify every historical file before producing any replacement.
        for artifact in &catalog.all {
            self.verify_artifact(request.case_id, artifact, cancel)?;
        }
        let workspace = TempWorkspace::new(&self.spool_dir(request.case_id)?)?;
        let fresh = ParquetStore::open_precise(&workspace.path)?;
        let (mut artifacts, choices) =
            self.convert_sources(request, &inputs, &old, &fresh, cancel)?;
        compact_replacements(&fresh, request.case_id, &mut artifacts, cancel)?;
        let generation = ParquetMigrationV1::generation(&old, irmind_app::sha256_stream)
            .map_err(|_| invalid_source())?;
        prepared::namespace(&fresh, request.case_id, &mut artifacts, generation.as_str())?;
        add_references(&old, &mut artifacts)?;
        let replacement = artifacts
            .iter()
            .cloned()
            .map(ParquetArtifact::from)
            .collect::<Vec<_>>();
        let record =
            ParquetMigrationV1::between(&old, &replacement, &choices, irmind_app::sha256_stream)
                .map_err(|_| invalid_source())?;
        Ok(Box::new(prepared::Prepared::new(
            self.case_dir(request.case_id)?,
            workspace,
            artifacts,
            record,
        )))
    }

    fn convert_sources(
        &self,
        request: &ArtifactMigrationRequest<'_>,
        inputs: &[inputs::Input],
        old: &[ParquetArtifact],
        fresh: &ParquetStore,
        cancel: &CancellationToken,
    ) -> Result<ConvertedSources, AppError> {
        let mut committed = irmind_app::artifact_catalog(request.signed_entries)?.active;
        let mut artifacts = Vec::new();
        let mut choices = BTreeMap::new();
        for input in inputs {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let parser = source_parser::SourceParser {
                inner: request.parser,
                logical: &input.manifest.source,
            };
            let mut replay = input.manifest.clone();
            replay.source.clone_from(&input.relative);
            self.rebuild_compare(
                request.case_id,
                &input.root,
                &[replay],
                old,
                &parser,
                cancel,
            )?;
            inputs::equivalent(input, request.parser, cancel)?;
            let paths = [input.relative.clone()];
            let result = fresh.prepare_local_batch(
                LocalBatchRequest {
                    case_id: request.case_id,
                    source_root: &input.root,
                    relative_paths: &paths,
                    copy_original: false,
                    parser: &parser,
                    committed_artifacts: &committed,
                    limits: request.limits,
                },
                cancel,
            )?;
            verify_replacement(fresh, request, input, &parser, &committed, &result, cancel)?;
            choices.insert(
                input.manifest.sha256.clone(),
                (input.parser_id.clone(), input.parser_version.clone()),
            );
            for source in result {
                if source.manifest.sha256 != input.manifest.sha256
                    || source.manifest.size != input.manifest.size
                {
                    return Err(AppError::EvidenceMismatch(
                        input.manifest.sha256.as_str().into(),
                    ));
                }
                for artifact in source.artifacts {
                    fresh.verify_artifact(request.case_id, &artifact, cancel)?;
                    let ParquetArtifact::V2(value) = &artifact else {
                        return Err(invalid_source());
                    };
                    artifacts.push(value.clone());
                    committed.push(artifact);
                }
            }
        }
        Ok((artifacts, choices))
    }
}

fn eligible(active: &[ParquetArtifact]) -> Result<Vec<ParquetArtifact>, AppError> {
    let hashes = active
        .iter()
        .filter(|a| matches!(a, ParquetArtifact::V1(_)))
        .flat_map(|a| a.source_hashes().iter().cloned())
        .collect::<BTreeSet<_>>();
    let old = active
        .iter()
        .filter(|a| a.source_hashes().iter().any(|h| hashes.contains(h)))
        .cloned()
        .collect::<Vec<_>>();
    if old.is_empty() {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyArtifactMigrationNotNeeded,
        ));
    }
    Ok(old)
}

fn add_references(old: &[ParquetArtifact], new: &mut [ParquetArtifactV2]) -> Result<(), AppError> {
    for value in new {
        let mut hashes = BTreeSet::new();
        // Prefer the retained single-source files; each bundle stays within
        // the existing 128-reference envelope limit.
        for source in &value.source_hashes {
            let previous = old
                .iter()
                .filter(|a| {
                    a.source_hashes().contains(source)
                        && super::format::same_family(a.schema_version(), value.schema.as_str())
                })
                .min_by_key(|a| (a.source_hashes().len(), a.path()))
                .ok_or_else(invalid_source)?;
            hashes.insert(previous.sha256().clone());
        }
        value.superseded_hashes = hashes.into_iter().collect();
        value.validate().map_err(|_| invalid_source())?;
    }
    Ok(())
}

fn compact_replacements(
    store: &ParquetStore,
    case: &CaseId,
    artifacts: &mut Vec<ParquetArtifactV2>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let mut groups: BTreeMap<Vec<u8>, Vec<ParquetArtifact>> = BTreeMap::new();
    for value in artifacts.iter() {
        let artifact: ParquetArtifact = value.clone().into();
        groups
            .entry(artifact.compaction_key())
            .or_default()
            .push(artifact);
    }
    for values in groups.values_mut() {
        values.sort_by(|a, b| a.source_hashes().cmp(b.source_hashes()));
        // Migration envelopes carry both source hashes and supersession
        // hashes; leave headroom within the unchanged 16 KiB wire ceiling.
        for chunk in values.chunks(64).filter(|c| c.len() > 1) {
            let ParquetArtifact::V2(compacted) =
                store.compact_signed_sources(case, chunk, cancel)?
            else {
                return Err(invalid_source());
            };
            artifacts.push(compacted);
        }
    }
    Ok(())
}
fn verify_replacement(
    fresh: &ParquetStore,
    request: &ArtifactMigrationRequest<'_>,
    input: &inputs::Input,
    parser: &dyn StreamingEventParser,
    seed: &[ParquetArtifact],
    expected: &[irmind_app::PreparedSource],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let workspace = TempWorkspace::new(&fresh.spool_dir(request.case_id)?)?;
    let replay = ParquetStore::open_precise(&workspace.path)?;
    let paths = [input.relative.clone()];
    let rebuilt = replay.prepare_local_batch(
        LocalBatchRequest {
            case_id: request.case_id,
            source_root: &input.root,
            relative_paths: &paths,
            copy_original: false,
            parser,
            committed_artifacts: seed,
            limits: request.limits,
        },
        cancel,
    )?;
    let actual = rebuilt
        .iter()
        .flat_map(|s| s.artifacts.iter())
        .collect::<Vec<_>>();
    let signed = expected
        .iter()
        .flat_map(|s| s.artifacts.iter())
        .collect::<Vec<_>>();
    if actual != signed {
        return Err(AppError::EvidenceMismatch(
            input.manifest.sha256.as_str().into(),
        ));
    }
    Ok(())
}
