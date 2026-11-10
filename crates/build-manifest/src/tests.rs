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

#[test]
fn serialized_paths_use_utf8_slash_order_including_nested_and_numbered_names() {
    let root = tempfile::tempdir().unwrap();
    let module = fixture(root.path(), false);
    fs::create_dir_all(module.join("src/fragment")).unwrap();
    fs::write(module.join("src/fragment/inner.rs"), "// nested\n").unwrap();
    fs::write(module.join("src/fragment2.rs"), "// numbered\n").unwrap();
    let bytes = manifest(root.path(), &module, vec![]).unwrap();
    let mut cursor = b"irmind-native-mapping-build-v1\0".len();
    let u64_at = |offset: &mut usize| {
        let value = usize::try_from(u64::from_be_bytes(
            bytes[*offset..*offset + 8].try_into().unwrap(),
        ))
        .unwrap();
        *offset += 8;
        value
    };
    assert_eq!(u64_at(&mut cursor), 0);
    let count = u64_at(&mut cursor);
    let mut paths = Vec::new();
    for _ in 0..count {
        let len = u64_at(&mut cursor);
        paths.push(
            std::str::from_utf8(&bytes[cursor..cursor + len])
                .unwrap()
                .to_owned(),
        );
        cursor += len + 32;
    }
    assert_eq!(cursor, bytes.len());
    assert!(paths.windows(2).all(|p| p[0].as_bytes() < p[1].as_bytes()));
    let nested = paths
        .iter()
        .position(|p| p.ends_with("/fragment/inner.rs"))
        .unwrap();
    let numbered = paths
        .iter()
        .position(|p| p.ends_with("/fragment2.rs"))
        .unwrap();
    assert!(nested < numbered);
}

#[test]
fn shared_implementation_is_committed_and_parent_paths_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let module = fixture(root.path(), false);
    let shared = root.path().join("crates/mapping-tables");
    fs::create_dir_all(shared.join("src")).unwrap();
    fs::write(shared.join("Cargo.toml"), "synthetic shared package").unwrap();
    fs::write(shared.join("src/lib.rs"), "// shared implementation\n").unwrap();
    let original = manifest(root.path(), &module, vec![]).unwrap();
    let before =
        manifest_with_sources(root.path(), &module, vec![], &["crates/mapping-tables"]).unwrap();
    fs::write(
        shared.join("src/lib.rs"),
        "// changed shared implementation\n",
    )
    .unwrap();
    assert_ne!(
        before,
        manifest_with_sources(root.path(), &module, vec![], &["crates/mapping-tables"]).unwrap()
    );
    assert_eq!(original, manifest(root.path(), &module, vec![]).unwrap());
    assert!(manifest_with_sources(root.path(), &module, vec![], &["../outside"]).is_err());
}
