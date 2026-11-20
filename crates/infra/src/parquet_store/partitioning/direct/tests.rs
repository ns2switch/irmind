#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::mapped_ingest::CommittedArtifacts;

#[test]
fn azure_sort_space_is_checked_before_creating_normalized_files() {
    use irmind_app::{FixedAppError, source_mapping::MappingCatalog};
    use irmind_mod_parser_azure_flow::AzureFlowSourceDecoder;
    use std::{fs, sync::Arc};

    let root = tempfile::tempdir().unwrap();
    let blob =
        include_bytes!("../../../../../testkit/fixtures/parser-azure-flow/source/vnet.ndjson");
    let name = "flows.ndjson";
    fs::write(root.path().join(name), blob).unwrap();
    let catalog =
        Arc::new(MappingCatalog::freeze(vec![Arc::new(AzureFlowSourceDecoder)], vec![]).unwrap());
    let parser = catalog
        .decoder_selection("parser-azure-flow", "azure-flow-source-v1")
        .unwrap();
    let store = ParquetStore::open_mapped(&root.path().join("case-data"), catalog).unwrap();
    let case = irmind_domain::CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let paths = [name.into()];
    let request = MappedIngestRequest {
        case_id: &case,
        source_root: root.path(),
        relative_paths: &paths,
        copy_original: true,
        parser: &parser,
        committed_artifacts: CommittedArtifacts::Slice(&[]),
        limits: irmind_app::PartitionLimits::default(),
    };
    let cancel = CancellationToken::new();
    let raw = blob.len() as u64;
    let normalized = super::super::staging::standard_allowance(raw).unwrap();
    let required = 3 * normalized + 16 * raw + raw + 5 * 64 * 1024 * 1024;
    let spool = store.spool_dir(&case).unwrap();
    assert!(matches!(
        store.preflight_direct_group_with_space(&request, 4, &cancel, || Ok(required - 1)),
        Err(AppError::Fixed(FixedAppError::StorageCaseStagingCapacity {
            required: reported, available
        })) if reported == required && available == required - 1
    ));
    assert_eq!(fs::read_dir(spool).unwrap().count(), 0);
    assert!(
        store
            .preflight_direct_group_with_space(&request, 4, &cancel, || Ok(required))
            .is_ok()
    );

    let paths = [
        "a.ndjson".into(),
        "b.ndjson".into(),
        "c.ndjson".into(),
        name.into(),
    ];
    for path in &paths[..3] {
        fs::write(root.path().join(path), blob).unwrap();
    }
    let group = MappedIngestRequest {
        relative_paths: &paths,
        ..request
    };
    let required = 8 * normalized + 4 * (16 * raw + raw) + 5 * 64 * 1024 * 1024;
    assert!(matches!(
        store.preflight_direct_group_with_space(&group, 4, &cancel, || Ok(required - 1)),
        Err(AppError::Fixed(FixedAppError::StorageCaseStagingCapacity {
            required: reported, available
        })) if reported == required && available == required - 1
    ));
    assert!(
        store
            .preflight_direct_group_with_space(&group, 4, &cancel, || Ok(required))
            .is_ok()
    );
}

#[test]
fn metadata_planning_bounds_raw_bytes_but_accepts_one_large_source() {
    let root = tempfile::tempdir().unwrap();
    for (name, size) in [
        ("a.json", RAW_GROUP_TARGET / 2),
        ("b.json", RAW_GROUP_TARGET / 2),
        ("c.json", 1),
    ] {
        std::fs::File::create(root.path().join(name))
            .unwrap()
            .set_len(size)
            .unwrap();
    }
    let paths = ["a.json".into(), "b.json".into(), "c.json".into()];
    let case = irmind_domain::CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let request = MappedIngestRequest {
        case_id: &case,
        source_root: root.path(),
        relative_paths: &paths,
        copy_original: false,
        parser: &irmind_mod_parser_json::JsonParser,
        committed_artifacts: CommittedArtifacts::Slice(&[]),
        limits: irmind_app::PartitionLimits::default(),
    };
    assert_eq!(
        ParquetStore::direct_group_paths(&request, &CancellationToken::new()).unwrap(),
        paths[..2]
    );
    std::fs::File::options()
        .write(true)
        .open(root.path().join("a.json"))
        .unwrap()
        .set_len(RAW_GROUP_TARGET + 1)
        .unwrap();
    assert_eq!(
        ParquetStore::direct_group_paths(&request, &CancellationToken::new()).unwrap(),
        paths[..1]
    );
    let token = CancellationToken::new();
    token.cancel();
    assert!(matches!(
        ParquetStore::direct_group_paths(&request, &token),
        Err(AppError::Cancelled)
    ));
}

#[test]
fn mixed_order_group_only_creates_row_spools_for_disordered_sources() {
    use irmind_app::source_mapping::MappingCatalog;
    use irmind_mod_mapping_json_compat::JsonCompatibilityMapping;
    use irmind_mod_parser_json::JsonSourceDecoder;
    use std::sync::Arc;

    let root = tempfile::tempdir().unwrap();
    let paths: Vec<_> = (0..4)
        .map(|index| {
            let name = format!("source-{index}.ndjson");
            let time = if index % 2 == 0 {
                ["00", "01"]
            } else {
                ["01", "00"]
            };
            let rows = time.map(|second| {
                format!(
                    r#"{{"eventTime":"2026-11-01T00:00:{second}Z","eventName":"Synthetic{index}"}}"#
                )
            });
            std::fs::write(root.path().join(&name), rows.join("\n")).unwrap();
            name
        })
        .collect();
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder)],
            vec![Arc::new(JsonCompatibilityMapping::new().unwrap())],
        )
        .unwrap(),
    );
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let mut store = ParquetStore::open_mapped(root.path(), catalog).unwrap();
    let profile = Arc::new(crate::parquet_store::ParquetProfile::default());
    store.attach_profile(profile.clone());
    let id = irmind_domain::CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let request = MappedIngestRequest {
        case_id: &id,
        source_root: root.path(),
        relative_paths: &paths,
        copy_original: false,
        parser: &parser,
        committed_artifacts: CommittedArtifacts::Slice(&[]),
        limits: irmind_app::PartitionLimits::default(),
    };
    let prepared = store
        .prepare_direct(&request, &CancellationToken::new())
        .unwrap()
        .unwrap();
    assert_eq!(prepared.metadata().sources.len(), 4);
    assert_eq!(profile.staged_sources(), 2);
    drop(prepared);
    let spool = store.case_dir(&id).unwrap().join("spool");
    assert_eq!(std::fs::read_dir(spool).unwrap().count(), 0);
}

#[test]
fn fdr_direct_group_aborts_when_the_gzip_grows_after_admission() {
    use irmind_app::{SourceFailureReason, source_mapping::MappingCatalog};
    use irmind_mod_parser_fdr::FdrSourceDecoder;
    use std::{fs, io::Write as _, sync::Arc};

    let root = tempfile::tempdir().unwrap();
    let case = irmind_domain::CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let cancel = CancellationToken::new();
    let name = "source.gz";
    let paths = [name.into()];
    let source = root.path().join(name);
    let gzip = include_bytes!("../../../../../../fuzz/seeds/parser_fdr/synthetic.ndjson.gz");
    fs::write(&source, gzip).unwrap();
    let catalog =
        Arc::new(MappingCatalog::freeze(vec![Arc::new(FdrSourceDecoder)], vec![]).unwrap());
    let parser = catalog
        .decoder_selection("parser-fdr", "fdr-source-v1")
        .unwrap();
    let store = ParquetStore::open_mapped(&root.path().join("case-data"), catalog.clone()).unwrap();
    let request = MappedIngestRequest {
        case_id: &case,
        source_root: root.path(),
        relative_paths: &paths,
        copy_original: false,
        parser: &parser,
        committed_artifacts: CommittedArtifacts::Slice(&[]),
        limits: irmind_app::PartitionLimits::default(),
    };
    let reservations = store.preflight_direct_group(&request, 4, &cancel).unwrap();

    // Expand the valid original after preflight and before hashing/normalizing.
    let mut mutated = fs::OpenOptions::new().append(true).open(&source).unwrap();
    mutated.write_all(gzip).unwrap();
    drop(mutated);

    let inputs = store
        .direct_inputs(&request, &paths, 4, &reservations, &cancel)
        .unwrap();
    let identity = request.parser.identity_for_source(name).unwrap();
    let routes = crate::parquet_store::mapped::projection_routes_for_direct(&catalog)
        .unwrap()
        .into_iter()
        .map(|(mapping, route)| (route, mapping))
        .collect();
    let mut writer = DirectWriting::new(group_identity(&request, identity), identity, routes, None);
    let mut allocator = super::super::Allocator::from_signed(&[], request.limits).unwrap();
    let failure = store
        .stream_direct_chunk(&request, inputs, &mut writer, &mut allocator, &cancel)
        .err()
        .unwrap();
    assert!(
        matches!(&failure, AppError::SourceFailure(rejected)
            if rejected.source() == name && rejected.reason() == SourceFailureReason::Limit),
        "{failure:?}"
    );
    drop(writer);
    assert_eq!(
        fs::read_dir(store.spool_dir(&case).unwrap())
            .unwrap()
            .count(),
        0
    );
}
