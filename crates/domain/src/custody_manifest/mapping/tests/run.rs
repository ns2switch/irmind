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

#[test]
fn confirmed_time_context_is_typed_bounded_and_bound_to_the_manifest() {
    let context =
        SourceTimeContextV1::try_new(2026, -210, true, SourceTimeBasisV1::Command).unwrap();
    assert_eq!(
        SourceTimeContextV1::parse(&context.snapshot()).unwrap(),
        context
    );
    let mut manifest = super::source_manifest();
    assert!(
        SourceRecordSetV1::from_manifest_with_time(
            &manifest,
            super::source().reference().clone(),
            super::source().formats().to_vec(),
            2,
            hash('b'),
            Some(context)
        )
        .is_err()
    );
    manifest.timestamp_context = Some(context.snapshot());
    let value = SourceRecordSetV1::from_manifest_with_time(
        &manifest,
        super::source().reference().clone(),
        super::source().formats().to_vec(),
        2,
        hash('b'),
        Some(context),
    )
    .unwrap();
    assert_eq!(value.time_context(), Some(context));
    assert_eq!(
        value.encode().unwrap(),
        include_str!("../goldens/source-set-time-v1.hex").trim()
    );
    assert_eq!(
        SourceRecordSetV1::decode(&value.encode().unwrap()).unwrap(),
        value
    );
    value.validate_manifest(&manifest).unwrap();
    for (year, offset) in [(0, 0), (10000, 0), (2026, -1440), (2026, 1440)] {
        assert!(
            SourceTimeContextV1::try_new(year, offset, true, SourceTimeBasisV1::Analyst).is_err()
        );
    }
    for text in [
        "source-time-v1;year=2026;offset=+0;rollover=1;basis=command",
        "source-time-v1;year=2026;offset=0;rollover=2;basis=command",
        "source-time-v1;year=2026;offset=0;rollover=1;basis=unknown",
    ] {
        assert!(SourceTimeContextV1::parse(text).is_err());
    }
}
