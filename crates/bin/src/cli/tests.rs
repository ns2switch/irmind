use super::*;

#[test]
fn no_arguments_selects_the_workspace_without_an_llm() {
    let cli = Cli::try_parse_from(["irmind"]).unwrap();
    assert!(cli.command.is_none());
    assert!(cli.llm_module.is_none());
}

#[test]
fn walks_ingest_directory_in_stable_order() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("nested")).unwrap();
    std::fs::write(root.path().join("b.json"), b"{}").unwrap();
    std::fs::write(root.path().join("a.json"), b"{}").unwrap();
    std::fs::write(root.path().join("nested/c.json"), b"{}").unwrap();
    let files = input_files(root.path()).unwrap();
    let names = files
        .iter()
        .map(|path| path.strip_prefix(root.path()).unwrap().to_path_buf())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            PathBuf::from("a.json"),
            PathBuf::from("b.json"),
            PathBuf::from("nested/c.json")
        ]
    );
    assert_eq!(
        audit_source_name(root.path(), &files[2]).unwrap(),
        "nested/c.json"
    );
    assert_eq!(audit_source_name(&files[0], &files[0]).unwrap(), "a.json");
}

#[cfg(unix)]
#[test]
fn rejects_symlink_inside_ingest_directory() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("real.json"), b"{}").unwrap();
    std::os::unix::fs::symlink("real.json", root.path().join("link.json")).unwrap();
    assert!(input_files(root.path()).is_err());
}

#[cfg(unix)]
#[test]
fn evidence_reader_refuses_a_swapped_symlink() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.json");
    std::fs::write(&target, b"{}").unwrap();
    let link = root.path().join("swapped.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(super::read_evidence(&link).is_err());
}

#[cfg(unix)]
#[test]
fn ingest_errors_escape_control_characters_in_file_names() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.json");
    std::fs::write(&target, b"synthetic").unwrap();
    let malicious = root.path().join("bad\u{1b}[31m.txt");
    std::os::unix::fs::symlink(&target, &malicious).unwrap();
    let error = input_files(root.path()).unwrap_err().to_string();
    assert!(!error.contains('\u{1b}'));
    assert!(error.contains("\\u{1b}"));
}
