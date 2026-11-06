#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![cfg(all(feature = "keystore-file", feature = "parser-json"))]

use irmind_app::{AuditLog, SignerBackend as _, artifact_catalog, hex, sha256};
use irmind_domain::{Actor, CaseId, ParquetArtifact};
use irmind_mod_keystore_file::FileKeystore;
use secrecy::SecretString;
use std::{
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

const PASSPHRASE: &str = "Synthetic CLI precise-ingestion test passphrase";

fn configure(root: &Path) {
    let backend =
        FileKeystore::open(root, &SecretString::from(PASSPHRASE.to_owned()), true).unwrap();
    let signer = backend.create(Actor::Analyst).unwrap();
    let fingerprint = hex(&sha256(&signer.public_key()));
    let config = root.join("keystore.toml");
    std::fs::write(&config, format!("[keystore]\nsigner = \"file\"\nsecrets = \"file\"\nanalyst_key_fingerprint = \"{fingerprint}\"\n")).unwrap();
    irmind_fs::private_file(&config).unwrap();
}

fn run(root: &Path, args: &[&str]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irmind"))
        .arg("--home")
        .arg(root)
        .args(["--passphrase-fd", "0"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSPHRASE}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn automation_ingests_precise_artifacts_by_default_without_an_implicit_migration() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("data");
    std::fs::create_dir(&home).unwrap();
    configure(&home);
    let id = run(
        &home,
        &["case", "new", "Synthetic CLI case", "--scope", "local only"],
    );
    let id = CaseId::parse(id.trim()).unwrap();
    let input = root.path().join("events.json");
    std::fs::write(&input, br#"{"Records":[{"eventTime":"2026-11-01T00:00:00.000001900Z","eventName":"SyntheticLogin"}]}"#).unwrap();
    run(&home, &["ingest", id.as_str(), input.to_str().unwrap()]);
    let store = irmind_infra::LocalStore::open(&home).unwrap();
    let before = store.entries(&id).unwrap();
    let catalog = artifact_catalog(&before).unwrap();
    assert_eq!(catalog.active.len(), 3);
    assert!(
        catalog
            .active
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V2(_)))
    );
    drop(store);
    run(&home, &["case", "show", id.as_str()]);
    let store = irmind_infra::LocalStore::open(&home).unwrap();
    let after = store.entries(&id).unwrap();
    assert_eq!(
        before.iter().map(|e| e.hash).collect::<Vec<_>>(),
        after.iter().map(|e| e.hash).collect::<Vec<_>>()
    );
}
