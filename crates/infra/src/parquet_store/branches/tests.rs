use super::*;
use irmind_app::LargeCaseStore;
use std::collections::BTreeMap;

fn fixture() -> CheckedBranchChunk {
    let keys: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../docs/development/subagent-format-vectors/public-keys.json"
    ))
    .unwrap();
    let agent = hex::decode(keys["agent"].as_str().unwrap()).unwrap();
    CheckedBranchChunk::decode(
        include_bytes!(
            "../../../../../docs/development/subagent-format-vectors/branch-chunk-0.json"
        ),
        &agent,
        &crate::LocalVerifier {
            trusted: BTreeMap::new(),
        },
    )
    .unwrap()
}
fn case() -> CaseId {
    CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap()
}
fn pending(store: &ParquetStore) -> usize {
    fs::read_dir(store.spool_dir(&case()).unwrap())
        .unwrap()
        .count()
}

#[test]
fn branch_chunks_are_private_case_local_immutable_and_checked_before_read() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let cancel = CancellationToken::new();
    let chunk = fixture();
    let staged = store.stage(&case(), &chunk, &cancel).unwrap();
    assert_eq!(pending(&store), 1);
    let published = store.publish(staged).unwrap();
    assert_eq!(pending(&store), 0);
    let path = store
        .case_dir(&case())
        .unwrap()
        .join(published.reference.relative_path());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let read = store.read(&case(), &published.reference, &cancel).unwrap();
    assert_eq!(read.as_bytes(), chunk.bytes());
    let again = store
        .publish(store.stage(&case(), &chunk, &cancel).unwrap())
        .unwrap();
    assert_eq!(again.reference, published.reference);
    let different = CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    assert!(
        store
            .read(&different, &published.reference, &cancel)
            .is_err()
    );
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(store.read(&case(), &published.reference, &cancel).is_err());
    assert!(
        store
            .publish(store.stage(&case(), &chunk, &cancel).unwrap())
            .is_err()
    );
    assert_eq!(pending(&store), 0);
}

#[test]
fn branch_pending_files_are_removed_on_drop_cancel_error_and_recovery() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let chunk = fixture();
    let cancel = CancellationToken::new();
    drop(store.stage(&case(), &chunk, &cancel).unwrap());
    assert_eq!(pending(&store), 0);
    store
        .discard(store.stage(&case(), &chunk, &cancel).unwrap())
        .unwrap();
    assert_eq!(pending(&store), 0);
    let staged = store.stage(&case(), &chunk, &cancel).unwrap();
    cancel.cancel();
    assert!(matches!(store.publish(staged), Err(AppError::Cancelled)));
    assert_eq!(pending(&store), 0);
    assert!(matches!(
        store.stage(&case(), &chunk, &cancel),
        Err(AppError::Cancelled)
    ));
    let cancel = CancellationToken::new();
    let staged = store.stage(&case(), &chunk, &cancel).unwrap();
    let (case, reference, mut file, token) = staged.into_parts();
    file.as_file().set_len(2 * 1024 * 1024).unwrap();
    file.write_all(b"changed").unwrap();
    assert!(
        store
            .publish(StagedBranchChunk::new(case.clone(), reference, file, token))
            .is_err()
    );
    assert_eq!(pending(&store), 0);
    let staged = store.stage(&case, &chunk, &cancel).unwrap();
    let (_, _, file, _) = staged.into_parts();
    let (file, orphan) = file.keep().unwrap();
    drop(file);
    assert_eq!(store.clean_orphan_spools(&case).unwrap(), 1);
    assert!(!orphan.exists());
}

#[cfg(unix)]
#[test]
fn branch_reads_and_publication_refuse_links() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let cancel = CancellationToken::new();
    let chunk = fixture();
    let case_dir = store.case_dir(&case()).unwrap();
    let external = outside.path().join("must-not-change");
    fs::write(&external, b"keep").unwrap();
    std::os::unix::fs::symlink(outside.path(), case_dir.join("branches")).unwrap();
    assert!(
        store
            .publish(store.stage(&case(), &chunk, &cancel).unwrap())
            .is_err()
    );
    assert_eq!(fs::read(&external).unwrap(), b"keep");
    fs::remove_file(case_dir.join("branches")).unwrap();
    let published = store
        .publish(store.stage(&case(), &chunk, &cancel).unwrap())
        .unwrap();
    let path = case_dir.join(published.reference.relative_path());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&external, &path).unwrap();
    assert!(store.read(&case(), &published.reference, &cancel).is_err());
    assert_eq!(pending(&store), 0);
}
