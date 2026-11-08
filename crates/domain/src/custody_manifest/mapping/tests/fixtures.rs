use super::super::*;
use crate::{
    ARTIFACT_V2_MAX_DATE_TUPLES, ARTIFACT_V2_PARTITION_POLICY, ARTIFACT_V2_SCOPE_KEYS,
    ARTIFACT_V2_STABLE_ORDER, ARTIFACT_V2_TIME_SEMANTICS, ArtifactPartitionV2, ArtifactSchemaV2,
    COMMON_EVENT_BUILDER, ParquetArtifactV2,
};

pub(super) fn hash(letter: char) -> EvidenceHash {
    EvidenceHash::parse(&letter.to_string().repeat(64)).unwrap()
}
pub(super) fn mapped(
    letter: char,
    source_path: &str,
    part: &str,
    physical: char,
) -> ParquetArtifactV3 {
    let source = input(letter, source_path);
    let snapshot = super::snapshot();
    let profile = MappingProfileV1::try_new(
        vec![MappingInputRefV1::from_set(&source).unwrap()],
        vec![snapshot.reference().unwrap()],
    )
    .unwrap();
    let binding = MappingBindingV1::new(
        MappingInputRefV1::from_set(&source).unwrap(),
        profile.identity().unwrap(),
        profile.catalog_identity(),
        source.decoder().clone(),
        Some(snapshot.mapping().clone()),
    );
    let core = ParquetArtifactV2 {
        path: format!("date=2026-01-02/part-{part}.parquet"),
        size: 100,
        sha256: hash(physical),
        parser_id: "parser-json".into(),
        parser_version: "json-source-v1".into(),
        schema: ArtifactSchemaV2::CommonEvents,
        partition: ArtifactPartitionV2 {
            date: "2026-01-02".into(),
            key_set: ARTIFACT_V2_SCOPE_KEYS.into(),
            policy: ARTIFACT_V2_PARTITION_POLICY.into(),
            tuple_cap: ARTIFACT_V2_MAX_DATE_TUPLES,
            all_scope_overflow: false,
            scopes: vec![],
        },
        source_hashes: vec![hash(letter)],
        time_semantics: ARTIFACT_V2_TIME_SEMANTICS.into(),
        stable_order: ARTIFACT_V2_STABLE_ORDER.into(),
        builder_version: COMMON_EVENT_BUILDER.into(),
        superseded_hashes: vec![],
    };
    ParquetArtifactV3::try_new(core, ArtifactPipelineV1::mapped(vec![binding], 2).unwrap()).unwrap()
}
pub(super) fn parents() -> Vec<ParquetArtifactV3> {
    vec![
        mapped('a', "logs/synthetic.json", "a", 'e'),
        mapped('d', "logs/second.json", "b", 'f'),
    ]
}
pub(super) fn compact(parents: &[ParquetArtifactV3]) -> ParquetArtifactV3 {
    let bindings = ParquetLayoutV1::preserved_bindings(parents).unwrap();
    let mut core = parents[0].core().clone();
    core.path = "date=2026-01-02/part-c.parquet".into();
    core.size = 150;
    core.sha256 = hash('1');
    core.builder_version = PARQUET_LAYOUT_BUILDER_V1.into();
    core.source_hashes = bindings
        .iter()
        .map(|b| b.input().source().clone())
        .collect();
    let mut references = parents
        .iter()
        .map(|a| ArtifactParentV1::from_artifact(a).unwrap())
        .collect::<Vec<_>>();
    references.sort_by(|a, b| a.path().cmp(b.path()));
    let rows = parents.iter().map(|a| a.pipeline().rows()).sum();
    ParquetArtifactV3::try_new(
        core,
        ArtifactPipelineV1::layout(bindings, rows, references).unwrap(),
    )
    .unwrap()
}
pub(super) fn profile() -> MappingProfileV1 {
    MappingProfileV1::try_new(
        vec![MappingInputRefV1::from_set(&super::source()).unwrap()],
        vec![super::snapshot().reference().unwrap()],
    )
    .unwrap()
}
pub(super) fn route(source: char, accepted: u64) -> MappingRouteV1 {
    MappingRouteV1::try_new(
        hash(source),
        Some(super::snapshot().mapping().clone()),
        MappingCountsV1::try_new(accepted, 0, 0, 0).unwrap(),
    )
    .unwrap()
}

pub(super) fn manifest(letter: char, source_path: &str) -> crate::SourceManifestV2 {
    let mut manifest = super::source_manifest();
    manifest.source.source = source_path.into();
    manifest.source.sha256 = hash(letter);
    manifest
}
pub(super) fn input(letter: char, source_path: &str) -> SourceRecordSetV1 {
    SourceRecordSetV1::from_manifest(
        &manifest(letter, source_path),
        crate::SourceReferenceV1::file(source_path).unwrap(),
        vec![SourceFormatIdentityV1::try_new("json", "source-json-v1").unwrap()],
        2,
        hash('b'),
    )
    .unwrap()
}
pub(super) fn source_profile(letter: char, source_path: &str) -> MappingProfileV1 {
    MappingProfileV1::try_new(
        vec![MappingInputRefV1::from_set(&input(letter, source_path)).unwrap()],
        vec![super::snapshot().reference().unwrap()],
    )
    .unwrap()
}
