use super::super::*;
use super::fixtures::*;

#[test]
fn artifact_metadata_keeps_the_16_kib_ceiling_including_layout_bindings() {
    let a = parents().remove(0);
    let mut bindings = Vec::new();
    for i in 1..=128 {
        let source = EvidenceHash::parse(&format!("{i:064x}")).unwrap();
        let old = &a.bindings()[0];
        bindings.push(MappingBindingV1::new(
            MappingInputRefV1::try_new(source, old.input().set().clone(), 2).unwrap(),
            old.profile().clone(),
            old.catalog().clone(),
            old.decoder().clone(),
            old.mapping().cloned(),
        ));
    }
    let pipeline = ArtifactPipelineV1::mapped(bindings, 256).unwrap();
    let mut core = a.core().clone();
    core.source_hashes = pipeline
        .bindings()
        .iter()
        .map(|b| b.input().source().clone())
        .collect();
    assert!(ParquetArtifactV3::try_new(core, pipeline).is_err());
    assert_eq!(wire::MAX_ARTIFACT, 16 * 1024);
    let too_big = "00".repeat(wire::MAX_ARTIFACT + 1);
    assert!(ParquetArtifactV3::decode(&too_big).is_err());
}

#[test]
fn mapping_or_schema_mismatch_never_creates_a_layout_group() {
    let mut parents = parents();
    let second = &parents[1];
    let old = &second.bindings()[0];
    let different =
        crate::MappingIdentityV1::try_new("mapping-other", "1", crate::COMMON_EVENT_V1, hash('5'))
            .unwrap();
    let binding = MappingBindingV1::new(
        old.input().clone(),
        old.profile().clone(),
        old.catalog().clone(),
        old.decoder().clone(),
        Some(different),
    );
    parents[1] = ParquetArtifactV3::try_new(
        second.core().clone(),
        ArtifactPipelineV1::mapped(vec![binding], 2).unwrap(),
    )
    .unwrap();
    assert!(ParquetLayoutV1::preserved_bindings(&parents).is_err());
    let mut parents = super::fixtures::parents();
    let mut core = parents[1].core().clone();
    core.schema = crate::ArtifactSchemaV2::CommonEntities;
    parents[1] = ParquetArtifactV3::try_new(core, parents[1].pipeline().clone()).unwrap();
    assert!(ParquetLayoutV1::preserved_bindings(&parents).is_err());
}

#[test]
fn layout_references_require_canonical_unique_paths_and_envelope_identities() {
    let parents = parents();
    let child = compact(&parents);
    let mut references = parents
        .iter()
        .map(|a| ArtifactParentV1::from_artifact(a).unwrap())
        .collect::<Vec<_>>();
    references.reverse();
    assert!(ArtifactPipelineV1::layout(child.bindings().to_vec(), 4, references).is_err());
    let first = ArtifactParentV1::from_artifact(&parents[0]).unwrap();
    assert!(
        ArtifactPipelineV1::layout(child.bindings().to_vec(), 4, vec![first.clone(), first])
            .is_err()
    );
    assert!(ArtifactParentV1::try_new("../outside.parquet".into(), hash('6')).is_err());
    assert!(ArtifactParentV1::try_new("/absolute.parquet".into(), hash('6')).is_err());
    assert!(ArtifactPipelineV1::mapped(parents[0].bindings().to_vec(), 3).is_ok());
    assert!(
        ParquetArtifactV3::try_new(
            parents[0].core().clone(),
            ArtifactPipelineV1::mapped(parents[0].bindings().to_vec(), 3).unwrap()
        )
        .is_err()
    );
}
