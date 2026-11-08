use super::super::*;
use super::fixtures::*;

#[test]
fn mapped_and_layout_goldens_have_distinct_domains_and_unchanged_parent_bindings() {
    let parents = parents();
    let child = compact(&parents);
    assert_eq!(
        parents[0].encode().unwrap(),
        include_str!("../goldens/mapped-v3.hex").trim()
    );
    assert_eq!(
        child.encode().unwrap(),
        include_str!("../goldens/layout-v3.hex").trim()
    );
    for value in [&parents[0], &child] {
        assert_eq!(
            ParquetArtifactV3::decode(&value.encode().unwrap()).unwrap(),
            *value
        );
    }
    let receipt = ParquetLayoutV1::between(&parents, &child).unwrap();
    assert_eq!(
        receipt.encode().unwrap(),
        include_str!("../goldens/layout-receipt-v1.hex").trim()
    );
    assert_eq!(
        ParquetLayoutV1::decode(&receipt.encode().unwrap()).unwrap(),
        receipt
    );
    assert!(receipt.verify(&parents, &child).is_ok());
    assert_ne!(child.bindings()[0].profile(), child.bindings()[1].profile());
    assert_eq!(child.bindings()[0], parents[0].bindings()[0]);
    assert_eq!(child.bindings()[1], parents[1].bindings()[0]);
    assert!(ParquetArtifactV3::decode(&receipt.encode().unwrap()).is_err());
    assert!(ParquetLayoutV1::decode(&child.encode().unwrap()).is_err());
}

#[test]
fn layout_commitments_are_recalculated_from_complete_envelopes() {
    let parents = parents();
    let child = compact(&parents);
    let receipt = ParquetLayoutV1::between(&parents, &child).unwrap();
    assert!(receipt.verify(&parents[..1], &child).is_err());
    let mut changed = parents[0].core().clone();
    changed.sha256 = hash('2');
    let changed = ParquetArtifactV3::try_new(changed, parents[0].pipeline().clone()).unwrap();
    assert!(
        receipt
            .verify(&[changed, parents[1].clone()], &child)
            .is_err()
    );
    let mut changed = child.core().clone();
    changed.sha256 = hash('3');
    let changed = ParquetArtifactV3::try_new(changed, child.pipeline().clone()).unwrap();
    assert!(receipt.verify(&parents, &changed).is_err());
    let payload = receipt.encode().unwrap();
    let mut bytes = wire::decode(&payload, super::super::layout::TAG, wire::MAX_SMALL).unwrap();
    let counter = super::super::layout::TAG.len() + 8 + PARQUET_LAYOUT_BUILDER_V1.len();
    bytes[counter + 7] = 3;
    let changed = ParquetLayoutV1::decode(&wire::encode(&bytes, wire::MAX_SMALL).unwrap()).unwrap();
    assert!(changed.verify(&parents, &child).is_err());
    assert!(ParquetLayoutV1::decode(&(payload.clone() + "00")).is_err());
    assert!(ParquetLayoutV1::decode(&payload.to_ascii_uppercase()).is_err());
}

#[test]
fn layout_of_one_partition_keeps_the_original_complete_mapping_receipt() {
    let mut parents = parents();
    let first = &parents[0];
    parents[0] = ParquetArtifactV3::try_new(
        first.core().clone(),
        ArtifactPipelineV1::mapped(first.bindings().to_vec(), 1).unwrap(),
    )
    .unwrap();
    let mut other = parents[0].core().clone();
    other.partition.date = "2026-01-03".into();
    other.path = "date=2026-01-03/part-other.parquet".into();
    let other = ParquetArtifactV3::try_new(other, parents[0].pipeline().clone()).unwrap();
    let original = vec![parents[0].clone(), other];
    let run = MappingRunV1::between(&profile(), vec![route('a', 2)], &original).unwrap();
    let child = compact(&parents);
    let receipt = ParquetLayoutV1::between(&parents, &child).unwrap();
    assert_eq!(receipt.rows(), 3);
    assert!(run.verify(&profile(), &original).is_ok());
    assert!(run.verify(&profile(), &[child]).is_err());
}

#[test]
fn identical_file_bytes_are_distinct_derivations_and_conflicting_bindings_cannot_merge() {
    let a = parents().remove(0);
    let mut core = a.core().clone();
    core.path = "date=2026-01-02/part-other.parquet".into();
    let old = &a.bindings()[0];
    let binding = MappingBindingV1::new(
        old.input().clone(),
        hash('4'),
        old.catalog().clone(),
        old.decoder().clone(),
        old.mapping().cloned(),
    );
    let b = ParquetArtifactV3::try_new(core, ArtifactPipelineV1::mapped(vec![binding], 2).unwrap())
        .unwrap();
    assert_eq!(a.core().sha256, b.core().sha256);
    assert_ne!(a.identity().unwrap(), b.identity().unwrap());
    assert!(ParquetLayoutV1::preserved_bindings(&[a, b]).is_err());
}
