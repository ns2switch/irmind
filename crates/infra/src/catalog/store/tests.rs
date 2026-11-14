use super::*;
use crate::catalog::Ed25519CatalogIndexVerifier;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::catalog::{CatalogIndex, CatalogIndexVerifier, FrozenCatalogRelease};
use std::sync::OnceLock;

fn proof(sequence: u64, description: usize) -> VerifiedCatalogIndex {
    static KEYS: OnceLock<[[u8; 32]; 1]> = OnceLock::new();
    let signer = SigningKey::from_bytes(&[111; 32]);
    let keys = KEYS.get_or_init(|| [signer.verifying_key().to_bytes()]);
    let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../docs/development/catalog-format-vectors/index.json"
    ))
    .unwrap();
    value["release_sequence"] = sequence.into();
    value["key_id"] = irmind_app::hex(&irmind_app::sha256(&keys[0])).into();
    value["entries"][0]["coverage"]["description"] = "x".repeat(description).into();
    // Struct serialization fixes field order with either serde_json map feature.
    let typed: CatalogIndex = serde_json::from_value(value).unwrap();
    let index = serde_json::to_vec(&typed).unwrap();
    let raw = CatalogIndexBytes::new(index.clone(), &[0; 64]).unwrap();
    let signature = signer.sign(&raw.signature_preimage());
    Ed25519CatalogIndexVerifier::from_release_keys(keys)
        .unwrap()
        .verify(
            &CatalogIndexBytes::new(index, &signature.to_bytes()).unwrap(),
            &FrozenCatalogRelease::new("v0.1.0").unwrap(),
        )
        .unwrap()
}

#[test]
fn catalog_case_proof_is_independent_immutable_and_never_recovers_globally() {
    let root = tempfile::tempdir().unwrap();
    let store = FileCatalogProofStore::new(root.path());
    let cancel = CancellationToken::new();
    let a = CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap();
    let b = CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    let proof = proof(1, 8);
    let id = store.publish(&proof, &cancel).unwrap();
    assert!(store.read_for_case(&a, &id, &cancel).is_err());
    assert!(!root.path().join("parquet").exists());
    assert_eq!(store.publish_for_case(&a, &proof, &cancel).unwrap(), id);
    assert!(store.read_for_case(&b, &id, &cancel).is_err());
    let before = store.read_for_case(&a, &id, &cancel).unwrap();
    assert_eq!(store.publish_for_case(&a, &proof, &cancel).unwrap(), id);
    store.publish(&self::proof(2, 8), &cancel).unwrap();
    assert_eq!(
        store.read_for_case(&a, &id, &cancel).unwrap().index(),
        before.index()
    );
    let case_file = store.root(Some(&a), false).unwrap().join(filename(&id));
    fs::write(&case_file, b"changed").unwrap();
    assert!(store.read_for_case(&a, &id, &cancel).is_err());
    assert!(store.publish_for_case(&a, &proof, &cancel).is_err());
    assert!(store.read(&id, &cancel).is_ok());
    fs::remove_file(case_file).unwrap();
    assert!(store.read_for_case(&a, &id, &cancel).is_err());
    assert!(store.read(&id, &cancel).is_ok());
}

#[test]
fn catalog_proof_storage_is_private_and_cancelled_operations_leave_no_staging() {
    let root = tempfile::tempdir().unwrap();
    let store = FileCatalogProofStore::new(root.path());
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        store.publish(&proof(1, 8), &cancel),
        Err(AppError::Cancelled)
    ));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    let cancel = CancellationToken::new();
    let id = store.publish(&proof(1, 8), &cancel).unwrap();
    let dir = store.root(None, false).unwrap();
    let names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 2); // published proof and lock, no temporary.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in &names {
            assert_eq!(
                fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    cancel.cancel();
    assert!(matches!(store.read(&id, &cancel), Err(AppError::Cancelled)));
    assert!(preflight(MARGIN - 1, 1).is_err());
    assert!(preflight(u64::MAX, u64::MAX).is_err());
    assert!(preflight(MARGIN + 1, 1).is_ok());
}

#[test]
fn catalog_proof_count_and_byte_quotas_do_not_evict_or_cross_scopes() {
    let root = tempfile::tempdir().unwrap();
    let store = FileCatalogProofStore::new(root.path());
    let cancel = CancellationToken::new();
    let dir = store.root(None, true).unwrap();
    for i in 0..256u64 {
        fs::write(dir.join(format!("{i:064x}.proof")), b"occupied").unwrap();
    }
    let candidate = proof(1, 8);
    assert!(store.publish(&candidate, &cancel).is_err());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 257);
    let case = CaseId::parse("00000000-0000-0000-0000-000000000003").unwrap();
    store.publish_for_case(&case, &candidate, &cancel).unwrap();
    let case_dir = store.root(Some(&case), false).unwrap();
    assert!(quota(&case_dir, 16 * 1024 * 1024, 16 * 1024 * 1024, &cancel).is_err());
    assert!(quota(&case_dir, 16 * 1024 * 1024, 64 * 1024 * 1024, &cancel).is_ok());
    fs::write(case_dir.join(".proof-orphan"), b"unfinished").unwrap();
    store
        .publish_for_case(&case, &proof(2, 8), &cancel)
        .unwrap();
    assert!(!case_dir.join(".proof-orphan").exists());
}

#[test]
fn catalog_concurrent_publication_has_one_immutable_proof() {
    let root = tempfile::tempdir().unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let root = root.path();
            scope.spawn(move || {
                FileCatalogProofStore::new(root)
                    .publish(&proof(1, 8), &CancellationToken::new())
                    .unwrap();
            });
        }
    });
    let store = FileCatalogProofStore::new(root.path());
    assert_eq!(
        fs::read_dir(store.root(None, false).unwrap())
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn catalog_lock_wait_can_be_cancelled_without_staging_a_proof() {
    let root = tempfile::tempdir().unwrap();
    let store = FileCatalogProofStore::new(root.path());
    let dir = store.root(None, true).unwrap();
    let _held = lock(&dir, &CancellationToken::new()).unwrap();
    let cancel = CancellationToken::new();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| store.publish(&proof(1, 8), &cancel));
        std::thread::sleep(std::time::Duration::from_millis(30));
        cancel.cancel();
        assert!(matches!(waiter.join().unwrap(), Err(AppError::Cancelled)));
    });
    assert_eq!(fs::read_dir(dir).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn catalog_storage_rejects_symbolic_and_hard_links() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = FileCatalogProofStore::new(root.path());
    let cancel = CancellationToken::new();
    let candidate = proof(1, 8);
    let id = store.publish(&candidate, &cancel).unwrap();
    let path = store.root(None, false).unwrap().join(filename(&id));
    fs::hard_link(&path, outside.path().join("alias")).unwrap();
    assert!(store.read(&id, &cancel).is_err());
    fs::remove_file(outside.path().join("alias")).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(outside.path().join("foreign"), b"foreign").unwrap();
    std::os::unix::fs::symlink(outside.path().join("foreign"), &path).unwrap();
    assert!(store.read(&id, &cancel).is_err());
    assert!(store.publish(&candidate, &cancel).is_err());
    let a = CaseId::parse("00000000-0000-0000-0000-000000000004").unwrap();
    fs::create_dir(root.path().join("parquet")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("parquet").join(a.as_str()))
        .unwrap();
    assert!(store.publish_for_case(&a, &candidate, &cancel).is_err());
    assert!(!outside.path().join("catalog-proofs").exists());
}
