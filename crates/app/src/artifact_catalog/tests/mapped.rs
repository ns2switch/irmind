use super::*;
use irmind_domain::{
    ArtifactPipelineV1, MappingBindingV1, MappingCountsV1, MappingInputRefV1, MappingProfileV1,
    MappingRouteV1, MappingRunV1, ParquetArtifactV3, ParquetLayoutV1, SourceFormatIdentityV1,
    SourceRecordSetV1, SourceReferenceV1,
};

fn mapped_history() -> (Vec<SignedEntry>, Vec<ParquetArtifactV3>) {
    mapped_history_for(0, 2)
}

pub(super) fn mapped_history_for(
    group: usize,
    records: usize,
) -> (Vec<SignedEntry>, Vec<ParquetArtifactV3>) {
    let template = ParquetArtifactV3::decode(
        include_str!("../../../../domain/src/custody_manifest/mapping/goldens/mapped-v3.hex")
            .trim(),
    )
    .unwrap();
    let name = format!("mapped-{group}.json");
    let manifest = SourceManifestV2 {
        source: source(
            &name,
            EvidenceHash::from_bytes(crate::sha256(name.as_bytes())),
        ),
        parser_id: template.core().parser_id.clone(),
        parser_version: template.core().parser_version.clone(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: vec![],
    };
    let input = SourceRecordSetV1::from_manifest(
        &manifest,
        SourceReferenceV1::file(&name).unwrap(),
        vec![SourceFormatIdentityV1::try_new("json", "source-json-v1").unwrap()],
        records as u64,
        hash("3"),
    )
    .unwrap();
    let profile =
        MappingProfileV1::try_new(vec![MappingInputRefV1::from_set(&input).unwrap()], vec![])
            .unwrap();
    let binding = MappingBindingV1::new(
        MappingInputRefV1::from_set(&input).unwrap(),
        profile.identity().unwrap(),
        profile.catalog_identity(),
        input.decoder().clone(),
        None,
    );
    let mut parents = Vec::new();
    for suffix in 0..records {
        let mut core = template.core().clone();
        core.source_hashes = vec![manifest.source.sha256.clone()];
        core.path = format!(
            "{}part-{group}-{suffix:08}.parquet",
            core.partition.path_prefix().unwrap()
        );
        core.sha256 = EvidenceHash::from_bytes(crate::sha256(core.path.as_bytes()));
        parents.push(
            ParquetArtifactV3::try_new(
                core,
                ArtifactPipelineV1::mapped(vec![binding.clone()], 1).unwrap(),
            )
            .unwrap(),
        );
    }
    let run = MappingRunV1::between(
        &profile,
        vec![
            MappingRouteV1::try_new(
                manifest.source.sha256.clone(),
                None,
                MappingCountsV1::try_new(records as u64, records as u64, 0, 0).unwrap(),
            )
            .unwrap(),
        ],
        &parents,
    )
    .unwrap();
    let mut entries = vec![
        entry(AuditEventKind::SourceManifestV2, manifest.encode().unwrap()),
        entry(AuditEventKind::SourceRecordSetV1, input.encode().unwrap()),
        entry(AuditEventKind::MappingProfileV1, profile.encode().unwrap()),
    ];
    entries.extend(
        parents
            .iter()
            .map(|a| entry(AuditEventKind::ParquetArtifactV3, a.encode().unwrap())),
    );
    entries.push(entry(AuditEventKind::MappingRunV1, run.encode().unwrap()));
    (entries, parents)
}

#[test]
fn mapped_catalog_preserves_signed_order_and_receipt_gated_parent_retention() {
    let (mut entries, parents) = mapped_history();
    assert!(artifact_catalog(&entries[..entries.len() - 1]).is_err());
    let original = artifact_catalog(&entries).unwrap();
    assert_eq!(
        original.active,
        parents.iter().cloned().map(Into::into).collect::<Vec<_>>()
    );
    let child = ParquetLayoutV1::replacement(&parents, 123, hash("4")).unwrap();
    let receipt = ParquetLayoutV1::between(&parents, &child).unwrap();
    entries.push(entry(
        AuditEventKind::ParquetArtifactV3,
        child.encode().unwrap(),
    ));
    assert!(artifact_catalog(&entries).is_err());
    entries.push(entry(
        AuditEventKind::ParquetLayoutV1,
        receipt.encode().unwrap(),
    ));
    let catalog = artifact_catalog(&entries).unwrap();
    assert_eq!(catalog.all.len(), 3);
    assert_eq!(catalog.active, vec![child.into()]);
    let inventory = seal_inventory(&entries, &[]).unwrap();
    assert_eq!(
        irmind_domain::SealInventoryV2::decode(&inventory[0])
            .unwrap()
            .count,
        4
    );
    let mut altered = entries;
    altered.remove(3);
    assert!(artifact_catalog(&altered).is_err());
}

#[test]
fn common_physical_schemas_require_the_mapped_envelope_and_receipts() {
    let (entries, parents) = mapped_history();
    let mut catalog = ArtifactCatalogBuilder::default();
    catalog.accept(&entries[0]).unwrap();
    for parent in parents {
        let bare = entry(
            AuditEventKind::ParquetArtifactV2,
            parent.core().encode().unwrap(),
        );
        assert!(catalog.accept(&bare).is_err());
    }
    assert!(artifact_catalog(&entries).is_ok());
}
