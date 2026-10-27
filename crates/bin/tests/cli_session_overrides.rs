#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "keystore-file")]
#[test]
#[allow(clippy::too_many_lines)]
fn automation_records_effective_egress_override_in_signed_global_chain() {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use irmind_app::{AuditLog, SignerBackend as _, sha256};
    use irmind_domain::Actor;
    use irmind_mod_keystore_file::FileKeystore;
    use secrecy::SecretString;
    use std::{
        io::Write as _,
        process::{Command, Stdio},
    };

    let root = tempfile::tempdir().unwrap();
    let passphrase = "synthetic passphrase for a CLI integration test";
    let backend = FileKeystore::open(
        root.path(),
        &SecretString::from(passphrase.to_owned()),
        true,
    )
    .unwrap();
    let signer = backend.create(Actor::Analyst).unwrap();
    let public = signer.public_key();
    let fingerprint = irmind_app::hex(&sha256(&public));
    std::fs::write(
        root.path().join("keystore.toml"),
        format!("[keystore]\nsigner = \"file\"\nsecrets = \"file\"\nanalyst_key_fingerprint = \"{fingerprint}\"\n"),
    ).unwrap();
    irmind_fs::private_file(&root.path().join("keystore.toml")).unwrap();
    drop(signer);
    drop(backend);

    let mut child = Command::new(env!("CARGO_BIN_EXE_irmind"))
        .arg("--home")
        .arg(root.path())
        .args(["--passphrase-fd", "0", "case", "list"])
        .env("IRMIND_MODEL", "synthetic-cli-model")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{passphrase}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(passphrase));

    let store = irmind_infra::LocalStore::open(root.path()).unwrap();
    let entries = store.global_operations().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert!(entry.operation.starts_with("session-overrides-v1:"));
    assert!(
        entry
            .operation
            .contains(&irmind_app::hex(b"synthetic-cli-model"))
    );
    assert_eq!(entry.hash, sha256(&entry.canonical()));
    let verifying = VerifyingKey::from_bytes(&public.try_into().unwrap()).unwrap();
    verifying
        .verify(&entry.hash, &Signature::from_slice(&entry.sig).unwrap())
        .unwrap();
    drop(store);

    std::fs::write(
        root.path().join("config.toml"),
        "version = 1\nllm_module = \"llm-openai-compatible\"\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_irmind"))
        .arg("--home")
        .arg(root.path())
        .args(["--passphrase-fd", "0", "case", "list"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{passphrase}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("run irmind without a subcommand"));
}
