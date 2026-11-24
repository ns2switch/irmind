#![cfg(all(unix, feature = "keystore-file"))]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use irmind_app::{SignerBackend as _, hex, sha256};
use irmind_domain::{Actor, CaseId};
use irmind_mod_keystore_file::FileKeystore;
use secrecy::SecretString;
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const PASSPHRASE: &str = "Synthetic distribution test passphrase";
const TITLE: &str = "Synthetic Azure capture mapping startup";

#[test]
#[ignore = "requires the staged distribution executable with the default features"]
fn release_binary_reopens_case_with_azure_capture_mappers() {
    let binary = PathBuf::from(std::env::var_os("IRMIND_RELEASE_BINARY").unwrap());
    assert!(binary.is_absolute() && binary.is_file());
    let home = tempfile::tempdir().unwrap();
    let backend = FileKeystore::open(
        home.path(),
        &SecretString::from(PASSPHRASE.to_owned()),
        true,
    )
    .unwrap();
    let analyst = backend.create(Actor::Analyst).unwrap();
    let fingerprint = hex(&sha256(&analyst.public_key()));
    drop(analyst);
    drop(backend);
    let config = home.path().join("keystore.toml");
    fs::write(
        &config,
        format!(
            "[keystore]\nsigner = \"file\"\nsecrets = \"file\"\nanalyst_key_fingerprint = \"{fingerprint}\"\n"
        ),
    )
    .unwrap();
    irmind_fs::private_file(&config).unwrap();

    // The release executable registers all three Azure Analytics capture
    // aliases at startup, even with a local policy and no cloud credentials.
    let case = run(
        &binary,
        home.path(),
        &["case", "new", TITLE, "--scope", "local"],
    );
    let case = CaseId::parse(case.trim()).unwrap();
    let opened = run(&binary, home.path(), &["case", "show", case.as_str()]);
    assert!(opened.lines().any(|line| line == case.as_str()));
    assert!(opened.contains(TITLE));
    let verified = run(&binary, home.path(), &["verify", case.as_str()]);
    assert!(verified.contains("verified 1 audit entries"));
}

fn run(binary: &Path, home: &Path, args: &[&str]) -> String {
    let mut child = Command::new(binary)
        .env_clear()
        .arg("--home")
        .arg(home)
        .args(["--passphrase-fd", "0"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{PASSPHRASE}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{args:?} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
