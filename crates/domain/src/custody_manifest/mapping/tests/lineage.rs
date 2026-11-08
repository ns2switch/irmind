use super::super::*;
use super::fixtures::*;

fn ingest(history: &mut MappingLineageV1, letter: char, path: &str, artifact: &ParquetArtifactV3) {
    history.source(manifest(letter, path)).unwrap();
    history.input(input(letter, path)).unwrap();
    history.snapshot(super::snapshot()).unwrap();
    let profile = source_profile(letter, path);
    history.profile(profile.clone()).unwrap();
    history.artifact(artifact.clone()).unwrap();
    history
        .mapping_run(
            &MappingRunV1::between(
                &profile,
                vec![route(letter, 2)],
                std::slice::from_ref(artifact),
            )
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn mapping_outputs_stay_pending_until_complete_valid_receipt() {
    let mut history = MappingLineageV1::default();
    let a = parents().remove(0);
    history
        .source(manifest('a', "logs/synthetic.json"))
        .unwrap();
    history.input(input('a', "logs/synthetic.json")).unwrap();
    assert!(history.ensure_complete().is_err());
    assert!(history.profile(profile()).is_err());
    history.snapshot(super::snapshot()).unwrap();
    history.profile(profile()).unwrap();
    history.artifact(a.clone()).unwrap();
    assert!(history.has_pending());
    assert!(history.active().is_err());
    assert!(history.snapshot(super::snapshot()).is_err());
    let d = parents().remove(1);
    let wrong = MappingRunV1::between(
        &source_profile('d', "logs/second.json"),
        vec![route('d', 2)],
        &[d],
    )
    .unwrap();
    assert!(history.mapping_run(&wrong).is_err());
    let receipt = MappingRunV1::between(&profile(), vec![route('a', 2)], &[a]).unwrap();
    history.mapping_run(&receipt).unwrap();
    assert!(!history.has_pending());
    assert_eq!(history.active().unwrap().len(), 1);
    assert!(history.input(input('a', "logs/synthetic.json")).is_err());
}

#[test]
fn layout_activation_retains_parents_and_rejects_missing_or_reused_parents() {
    let mut history = MappingLineageV1::default();
    let parents = parents();
    ingest(&mut history, 'a', "logs/synthetic.json", &parents[0]);
    ingest(&mut history, 'd', "logs/second.json", &parents[1]);
    let child = compact(&parents);
    let receipt = ParquetLayoutV1::between(&parents, &child).unwrap();
    history.artifact(child.clone()).unwrap();
    assert!(history.ensure_complete().is_err());
    let mut changed = child.core().clone();
    changed.sha256 = hash('4');
    let changed = ParquetArtifactV3::try_new(changed, child.pipeline().clone()).unwrap();
    let wrong = ParquetLayoutV1::between(&parents, &changed).unwrap();
    assert!(history.layout(&wrong).is_err());
    history.layout(&receipt).unwrap();
    assert_eq!(history.all().unwrap().len(), 3);
    assert_eq!(history.active().unwrap(), vec![&child]);
    let mut reused = child.core().clone();
    reused.path = "date=2026-01-02/part-reused.parquet".into();
    let reused = ParquetArtifactV3::try_new(reused, child.pipeline().clone()).unwrap();
    assert!(history.artifact(reused).is_err());
    let mut missing = MappingLineageV1::default();
    ingest(&mut missing, 'a', "logs/synthetic.json", &parents[0]);
    assert!(missing.artifact(child).is_err());
}

#[test]
fn orphan_inputs_and_unknown_manifest_or_decoder_bindings_are_rejected() {
    let mut history = MappingLineageV1::default();
    assert!(history.input(input('a', "logs/synthetic.json")).is_err());
    history
        .source(manifest('a', "logs/synthetic.json"))
        .unwrap();
    history.input(input('a', "logs/synthetic.json")).unwrap();
    history.snapshot(super::snapshot()).unwrap();
    history.profile(profile()).unwrap();
    let a = parents().remove(0);
    let b = &a.bindings()[0];
    let binding = MappingBindingV1::new(
        b.input().clone(),
        b.profile().clone(),
        b.catalog().clone(),
        SourceDecoderIdentityV1::try_new("parser-json", "different-source-v1").unwrap(),
        b.mapping().cloned(),
    );
    let mut core = a.core().clone();
    core.parser_version = "different-source-v1".into();
    let changed =
        ParquetArtifactV3::try_new(core, ArtifactPipelineV1::mapped(vec![binding], 2).unwrap())
            .unwrap();
    assert!(history.artifact(changed).is_err());
    assert!(history.ensure_complete().is_err());
}
