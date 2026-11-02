use super::*;

#[test]
fn definitions_are_private_atomic_and_archives_survive_deactivation() {
    let root = tempfile::tempdir().unwrap();
    let store = FileDefinitionStore::new(root.path());
    assert!(
        store
            .read_active("parser-declarative-test")
            .unwrap()
            .is_none()
    );
    store
        .write_active("parser-declarative-test", "synthetic definition")
        .unwrap();
    let hash = hex(&sha256(b"synthetic definition"));
    store.archive(&hash, "synthetic definition").unwrap();
    assert_eq!(store.names().unwrap(), ["parser-declarative-test"]);
    assert_eq!(
        store
            .read_active("parser-declarative-test")
            .unwrap()
            .as_deref(),
        Some("synthetic definition")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(root.path().join("parsers/active"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(
                root.path()
                    .join("parsers/active/parser-declarative-test.toml")
            )
            .unwrap()
            .permissions()
            .mode()
                & 0o777,
            0o600
        );
    }
    assert!(
        fs::read_dir(root.path().join("parsers/active"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".definition-"))
    );
    store.deactivate("parser-declarative-test").unwrap();
    assert!(
        store
            .read_active("parser-declarative-test")
            .unwrap()
            .is_none()
    );
    assert!(
        root.path()
            .join(format!("parsers/archive/{hash}.toml"))
            .is_file()
    );
}

#[test]
fn definition_paths_and_size_fail_closed_without_partial_files() {
    let root = tempfile::tempdir().unwrap();
    let store = FileDefinitionStore::new(root.path());
    assert!(store.write_active("../escape", "synthetic").is_err());
    assert!(
        store
            .write_active("valid", &"x".repeat(MAX_DEFINITION_BYTES + 1))
            .is_err()
    );
    assert!(store.archive(&"a".repeat(64), "synthetic").is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn definition_store_does_not_follow_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let store = FileDefinitionStore::new(root.path());
    store.write_active("valid", "synthetic").unwrap();
    let target = root.path().join("outside.toml");
    fs::write(&target, "synthetic private value").unwrap();
    std::os::unix::fs::symlink(&target, root.path().join("parsers/active/link.toml")).unwrap();
    assert!(store.read_active("link").is_err());
    store.deactivate("link").unwrap();
    assert_eq!(
        fs::read_to_string(target).unwrap(),
        "synthetic private value"
    );
}

#[test]
fn orphan_definition_temporaries_are_removed_without_deleting_definitions() {
    let root = tempfile::tempdir().unwrap();
    let store = FileDefinitionStore::new(root.path());
    store.write_active("valid", "synthetic").unwrap();
    fs::write(
        root.path().join("parsers/active/.definition-orphan"),
        "synthetic",
    )
    .unwrap();
    assert_eq!(store.clean_temporary().unwrap(), 1);
    assert_eq!(
        store.read_active("valid").unwrap().as_deref(),
        Some("synthetic")
    );
    assert_eq!(store.clean_temporary().unwrap(), 0);
}
