#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::mapped_ingest::CommittedArtifacts;

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
