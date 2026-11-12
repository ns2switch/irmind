use super::*;
use irmind_domain::{MAX_SKILL_RESOURCE_BYTES, SkillResource};

fn package(text: &[u8]) -> SkillPackage {
    SkillPackage::new([SkillResource::new("SKILL.md", text).unwrap()]).unwrap()
}

#[test]
fn candidate_reads_are_bounded_cancelable_and_do_not_publish_or_modify_sources() {
    let root = tempfile::tempdir().unwrap();
    let candidate = tempfile::tempdir().unwrap();
    let source = candidate.path().join("SKILL.md");
    fs::write(&source, b"synthetic methodology").unwrap();
    let store = FileSkillPackageStore::new(root.path());
    let cancel = CancellationToken::new();
    let loaded = store.read_candidate(candidate.path(), &cancel).unwrap();
    assert_eq!(loaded, package(b"synthetic methodology"));
    assert_eq!(fs::read(&source).unwrap(), b"synthetic methodology");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    cancel.cancel();
    assert!(matches!(
        store.read_candidate(candidate.path(), &cancel),
        Err(AppError::Cancelled)
    ));
    fs::write(&source, vec![b'x'; MAX_SKILL_RESOURCE_BYTES + 1]).unwrap();
    assert!(
        store
            .read_candidate(candidate.path(), &CancellationToken::new())
            .is_err()
    );
}

#[test]
fn private_generation_round_trip_replaces_atomically_and_cleans_only_owned_pending_files() {
    let root = tempfile::tempdir().unwrap();
    let store = FileSkillPackageStore::new(root.path());
    let name = SkillName::parse("con").unwrap();
    let first = package(b"first generation");
    let second = package(b"second generation");
    assert!(store.names().unwrap().is_empty());
    store.publish(&name, &first).unwrap();
    assert_eq!(store.read_active(&name).unwrap(), Some(first));
    store.publish(&name, &second).unwrap();
    assert_eq!(store.read_active(&name).unwrap(), Some(second));
    assert_eq!(store.names().unwrap(), vec![name.clone()]);
    let directory = root.path().join("skills/active");
    fs::write(directory.join(".skill-orphan"), b"partial").unwrap();
    assert_eq!(store.clean_temporary().unwrap(), 1);
    assert_eq!(store.clean_temporary().unwrap(), 0);
    assert_eq!(store.names().unwrap(), vec![name.clone()]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let path = directory.join(FileSkillPackageStore::filename(&name));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    store.deactivate(&name).unwrap();
    assert!(store.read_active(&name).unwrap().is_none());
    assert!(store.names().unwrap().is_empty());
}

#[test]
fn hard_linked_candidates_and_active_generations_are_rejected() {
    let home = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("SKILL.md"), b"synthetic method").unwrap();
    let alias = home.path().join("external-alias");
    fs::hard_link(source.path().join("SKILL.md"), &alias).unwrap();
    let store = FileSkillPackageStore::new(home.path());
    assert!(
        store
            .read_candidate(source.path(), &CancellationToken::new())
            .is_err()
    );
    fs::remove_file(alias).unwrap();
    let name = SkillName::parse("triage").unwrap();
    store.publish(&name, &package(b"synthetic method")).unwrap();
    let path = home
        .path()
        .join("skills/active")
        .join(FileSkillPackageStore::filename(&name));
    fs::hard_link(path, home.path().join("other-alias")).unwrap();
    assert!(store.read_active(&name).is_err());
}

#[cfg(unix)]
#[test]
fn linked_candidates_and_store_directories_cannot_escape_the_chosen_roots() {
    use std::os::unix::fs::symlink;
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("method"), b"outside method").unwrap();
    symlink(
        outside.path().join("method"),
        source.path().join("SKILL.md"),
    )
    .unwrap();
    let store = FileSkillPackageStore::new(home.path());
    assert!(
        store
            .read_candidate(source.path(), &CancellationToken::new())
            .is_err()
    );
    symlink(outside.path(), home.path().join("skills")).unwrap();
    assert!(
        store
            .publish(&SkillName::parse("triage").unwrap(), &package(b"method"))
            .is_err()
    );
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    assert_eq!(
        fs::read(outside.path().join("method")).unwrap(),
        b"outside method"
    );
}

#[test]
fn malformed_or_oversized_stored_containers_fail_without_echoing_content() {
    let home = tempfile::tempdir().unwrap();
    let store = FileSkillPackageStore::new(home.path());
    let name = SkillName::parse("triage").unwrap();
    store.publish(&name, &package(b"method")).unwrap();
    let path = home
        .path()
        .join("skills/active")
        .join(FileSkillPackageStore::filename(&name));
    for bytes in [
        b"PRIVATE_BAD_JSON".to_vec(),
        vec![b'x'; usize::try_from(MAX_STORED_BYTES).unwrap() + 1],
    ] {
        fs::write(&path, bytes).unwrap();
        let error = store.read_active(&name).unwrap_err();
        assert!(!format!("{error:?}{error}").contains("PRIVATE_BAD_JSON"));
    }
}
