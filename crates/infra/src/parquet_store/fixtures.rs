//! Test fixtures execute the current production decoder, mapper and publication path.
#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{MappedIngestRequest, mapped_ingest::CommittedArtifacts};
use irmind_domain::{ParserSelectionMode, SourceManifestV2};

pub(super) struct SourceFixture {
    pub(super) manifest: SourceManifestV1,
    pub(super) records: usize,
    pub(super) artifacts: Vec<ParquetArtifact>,
    pub(super) mapping: irmind_app::source_mapping::DecodedSourceCommitmentV1,
}

pub(super) fn store(root: &Path) -> ParquetStore {
    let catalog = irmind_app::source_mapping::MappingCatalog::freeze(
        vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
        vec![Arc::new(
            irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap(),
        )],
    )
    .unwrap();
    ParquetStore::open_mapped(root, Arc::new(catalog)).unwrap()
}
pub(super) fn parser() -> irmind_app::source_mapping::SourceDecoderSelection {
    irmind_app::source_mapping::SourceDecoderSelection::new(Arc::new(
        irmind_mod_parser_json::JsonSourceDecoder,
    ))
}

/// Separate calls model successive ingestions, needed by maintenance compaction tests.
pub(super) fn successive_sources(
    store: &ParquetStore,
    request: MappedIngestRequest<'_>,
    cancel: &CancellationToken,
) -> Result<Vec<SourceFixture>, AppError> {
    let mut committed = request
        .committed_artifacts
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut result = Vec::new();
    for path in request.relative_paths {
        let request = MappedIngestRequest {
            relative_paths: std::slice::from_ref(path),
            committed_artifacts: CommittedArtifacts::Slice(&committed),
            ..request
        };
        let mut prepared = store
            .prepare_mapped_ingest(request, cancel)?
            .ok_or_else(invalid_source)?;
        let source = prepared
            .metadata()
            .sources
            .first()
            .ok_or_else(invalid_source)?
            .clone();
        let identity = request.parser.identity_for_source(path)?;
        let manifest = SourceManifestV2 {
            source: source.manifest.clone(),
            parser_id: identity.name.into(),
            parser_version: identity.version.into(),
            confidence: 0,
            selection: ParserSelectionMode::Analyst,
            timestamp_context: Some(
                request
                    .parser
                    .timestamp_context()
                    .unwrap_or("normalized-utc")
                    .into(),
            ),
            rejected_records: source.report.rejected,
            rejected_sample: source.report.samples.clone(),
        };
        let bound = prepared.metadata().bind(&[manifest])?;
        prepared.publish(cancel)?;
        prepared.retain_committed();
        let artifacts = bound
            .artifacts
            .into_iter()
            .map(ParquetArtifact::V3)
            .collect::<Vec<_>>();
        committed.extend(artifacts.clone());
        result.push(SourceFixture {
            manifest: source.manifest,
            records: source.report.accepted,
            artifacts,
            mapping: source.decoded,
        });
    }
    Ok(result)
}

pub(super) fn one_source(
    store: &ParquetStore,
    case_id: &CaseId,
    source_root: &Path,
    relative_path: &str,
    copy_original: bool,
    cancel: &CancellationToken,
) -> Result<SourceFixture, AppError> {
    successive_sources(
        store,
        MappedIngestRequest {
            case_id,
            source_root,
            relative_paths: &[relative_path.into()],
            copy_original,
            parser: &parser(),
            committed_artifacts: CommittedArtifacts::Slice(&[]),
            limits: irmind_app::PartitionLimits::default(),
        },
        cancel,
    )?
    .pop()
    .ok_or_else(invalid_source)
}
