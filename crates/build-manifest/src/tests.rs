use super::*;

fn fixture(root: &Path, reverse: bool) -> PathBuf {
    fs::write(root.join("Cargo.toml"), "synthetic workspace").unwrap();
    fs::write(root.join("Cargo.lock"), "synthetic resolved dependencies").unwrap();
    let mut paths = vec![
        "crates/app",
        "crates/domain",
        "crates/build-manifest",
        "crates/modules/mapping-test",
    ];
    if reverse {
        paths.reverse();
    }
    for directory in paths {
        let dir = root.join(directory);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("Cargo.toml"), "synthetic package").unwrap();
        fs::write(dir.join("src/lib.rs"), "// synthetic source\n").unwrap();
    }
    root.join("crates/modules/mapping-test")
}

#[test]
fn logical_paths_features_and_input_hashes_are_independent_of_directory_order() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let one = fixture(first.path(), false);
    let two = fixture(second.path(), true);
    let before = manifest(first.path(), &one, vec!["a".into(), "b".into()]).unwrap();
    assert_eq!(
        before,
        manifest(second.path(), &two, vec!["b".into(), "a".into()]).unwrap()
    );
    assert!(
        !before
            .windows(first.path().as_os_str().len())
            .any(|w| w == first.path().as_os_str().as_encoded_bytes())
    );
    fs::write(two.join("src/lib.rs"), "// modified mapping\n").unwrap();
    assert_ne!(
        before,
        manifest(second.path(), &two, vec!["a".into(), "b".into()]).unwrap()
    );
}
