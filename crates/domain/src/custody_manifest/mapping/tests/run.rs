use super::super::*;
use super::fixtures::*;

#[test]
fn complete_mapping_run_matches_independent_golden_and_rejects_lost_or_duplicate_events() {
    let a = parents().remove(0);
    let run =
        MappingRunV1::between(&profile(), vec![route('a', 2)], std::slice::from_ref(&a)).unwrap();
    assert_eq!(
        run.encode().unwrap(),
        include_str!("../goldens/mapping-run-v1.hex").trim()
    );
    assert_eq!(MappingRunV1::decode(&run.encode().unwrap()).unwrap(), run);
    assert!(run.verify(&profile(), std::slice::from_ref(&a)).is_ok());
    assert!(run.verify(&profile(), &[]).is_err());
    let mut duplicate = a.core().clone();
    duplicate.path = "date=2026-01-02/part-duplicate.parquet".into();
    let duplicate = ParquetArtifactV3::try_new(duplicate, a.pipeline().clone()).unwrap();
    assert!(
        MappingRunV1::between(&profile(), vec![route('a', 2)], &[a.clone(), duplicate]).is_err()
    );
    assert!(
        MappingRunV1::between(&profile(), vec![route('a', 1)], std::slice::from_ref(&a)).is_err()
    );
    assert!(MappingRunV1::between(&profile(), vec![route('d', 2)], &[a]).is_err());
}

#[test]
fn signed_decoding_context_includes_rejections_and_manifest_fields() {
    let set = super::source();
    let manifest = super::source_manifest();
    assert!(set.validate_manifest(&manifest).is_ok());
    let mut changed = manifest.clone();
    changed.timestamp_context = Some("confirmed-context".into());
    assert!(set.validate_manifest(&changed).is_err());
    let mut changed = manifest.clone();
    changed.rejected_sample = vec!["synthetic rejected record".into()];
    assert!(set.validate_manifest(&changed).is_err());
    let mut changed = manifest;
    changed.rejected_records = 2;
    assert!(set.validate_manifest(&changed).is_err());
    assert_eq!(set.rejected(), 1);
}

#[test]
fn unmapped_counts_cannot_claim_mapped_events_and_diagnostic_counts_are_bounded() {
    assert!(MappingCountsV1::try_new(0, 0, 0, 0).is_err());
    assert!(MappingCountsV1::try_new(1, 2, 0, 0).is_err());
    assert!(MappingCountsV1::try_new(2, 1, 2, 0).is_err());
    assert!(
        MappingRouteV1::try_new(
            hash('a'),
            None,
            MappingCountsV1::try_new(2, 0, 0, 0).unwrap()
        )
        .is_err()
    );
    assert!(
        MappingRouteV1::try_new(
            hash('a'),
            None,
            MappingCountsV1::try_new(2, 2, 0, 0).unwrap()
        )
        .is_ok()
    );
}
