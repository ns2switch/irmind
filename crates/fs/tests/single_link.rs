#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

#[test]
fn opened_file_link_count_rejects_external_aliases_on_each_native_platform() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("method.md");
    std::fs::write(&input, b"synthetic method").unwrap();
    let file = std::fs::File::open(&input).unwrap();
    assert!(irmind_fs::regular_file_has_single_link(&file).unwrap());
    let alias = root.path().join("alias.md");
    std::fs::hard_link(&input, &alias).unwrap();
    assert!(!irmind_fs::regular_file_has_single_link(&file).unwrap());
    let other = std::fs::File::open(&alias).unwrap();
    assert!(!irmind_fs::regular_file_has_single_link(&other).unwrap());
    std::fs::remove_file(alias).unwrap();
    assert!(irmind_fs::regular_file_has_single_link(&file).unwrap());
}
