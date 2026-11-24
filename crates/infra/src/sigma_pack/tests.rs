use super::*;

fn synthetic_rule(raw: &[u8]) -> Result<SigmaRuleIdentity, AppError> {
    if !raw.starts_with(b"fixture") {
        return Err(invalid());
    }
    Ok(SigmaRuleIdentity {
        id: None,
        version: None,
        author: Some("Synthetic".into()),
    })
}

#[test]
fn local_sigma_pack_pins_sorted_paths_and_exact_rule_bytes() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(root.path().join("z.yml"), b"fixture two\n").unwrap();
    fs::write(nested.join("m.yaml"), b"fixture one\r\n").unwrap();
    fs::write(root.path().join("LICENSE"), b"synthetic").unwrap();
    let pack =
        read_local_sigma_pack(root.path(), &CancellationToken::new(), synthetic_rule).unwrap();
    assert_eq!(pack.manifest.0[0].path, "nested/m.yaml");
    assert_eq!(pack.manifest.0[1].path, "z.yml");
    assert_eq!(
        pack.rules,
        [b"fixture one\r\n".to_vec(), b"fixture two\n".to_vec()]
    );
    for (rule, bytes) in pack.manifest.0.iter().zip(pack.rules) {
        assert_eq!(rule.rule.sha256, irmind_app::sha256(&bytes));
        assert_eq!(rule.size, bytes.len() as u64);
    }
}

#[test]
fn local_sigma_pack_rejects_hard_links_limits_and_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let rule = root.path().join("test.yml");
    fs::write(&rule, b"fixture").unwrap();
    let extra = root.path().join("alias.yaml");
    fs::hard_link(&rule, &extra).unwrap();
    let cancel = CancellationToken::new();
    assert!(read_local_sigma_pack(root.path(), &cancel, synthetic_rule).is_err());
    fs::remove_file(extra).unwrap();
    assert!(read_local_sigma_pack(root.path(), &cancel, synthetic_rule).is_ok());
    fs::write(&rule, vec![b' '; 65_537]).unwrap();
    assert!(read_local_sigma_pack(root.path(), &cancel, synthetic_rule).is_err());
    cancel.cancel();
    assert!(matches!(
        read_local_sigma_pack(root.path(), &cancel, synthetic_rule),
        Err(AppError::Cancelled)
    ));
}

#[cfg(unix)]
#[test]
fn local_sigma_pack_rejects_symbolic_links_even_for_non_rule_names() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let rule = outside.path().join("external.yml");
    fs::write(&rule, b"fixture").unwrap();
    std::os::unix::fs::symlink(&rule, root.path().join("license")).unwrap();
    assert!(read_local_sigma_pack(root.path(), &CancellationToken::new(), synthetic_rule).is_err());
}
