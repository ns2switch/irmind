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
