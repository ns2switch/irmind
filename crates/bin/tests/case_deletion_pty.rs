#![forbid(unsafe_code)]
#![cfg(all(feature = "keystore-file", feature = "parser-json"))]
#![allow(clippy::unwrap_used)]
use irmind_app::{CryptoPorts, Engine, EnginePorts, SignerBackend, hex, sha256};
use irmind_domain::{Actor, ExecutionMode};
use irmind_infra::{LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
use irmind_security::MandatoryGuard;
use secrecy::SecretString;
use std::{path::Path, process::Command, sync::Arc};
#[path = "support/current_sources.rs"]
mod current_sources;
#[path = "support/demo_session.rs"]
mod demo_session;
#[path = "support/terminal_screen.rs"]
mod terminal_screen;
use demo_session::DemoSession;
const PHRASE: &str = "Synthetic case deletion PTY passphrase";
const TITLE: &str = "Synthetic deletion PTY";
fn seed(root: &Path) {
    let backend = FileKeystore::open(root, &SecretString::from(PHRASE.to_owned()), true).unwrap();
    let signer = backend.create(Actor::Analyst).unwrap();
    let store = Arc::new(current_sources::open(root));
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    engine.create_case(TITLE, "local only").unwrap();
    let config = root.join("keystore.toml");
    std::fs::write(
        &config,
        format!(
            "[keystore]\nsigner = \"file\"\nsecrets = \"file\"\nanalyst_key_fingerprint = \"{}\"\n",
            hex(&sha256(&signer.public_key()))
        ),
    )
    .unwrap();
    irmind_fs::private_file(&config).unwrap();
}
fn command(root: &Path) -> Command {
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args(["-c", "stty cols 100 rows 32; exec \"$0\" --home \"$1\""])
            .arg(env!("CARGO_BIN_EXE_irmind"))
            .arg(root);
        c
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd.exe");
        c.args(["/d", "/c", "chcp", "65001", ">nul", "&&"])
            .arg(env!("CARGO_BIN_EXE_irmind"))
            .arg("--home")
            .arg(root)
            .args(["<CONIN$", ">CONOUT$", "2>&1"]);
        c
    };
    cmd.env("TERM", "xterm-256color").env("NO_COLOR", "1");
    cmd
}
#[test]
fn case_deletion_from_open_tui_releases_session_then_signs_and_lists_tombstone() {
    let root = tempfile::tempdir().unwrap();
    seed(root.path());
    let mut session = DemoSession::spawn_sized(&command(root.path()), 100, 32).unwrap();
    session.timeout = std::time::Duration::from_secs(45);
    session.expect("Unlock").unwrap();
    session.send(format!("{PHRASE}\r")).unwrap();
    session.expect("Fingerprint").unwrap();
    session.send("\r").unwrap();
    session.expect("Find cases or type").unwrap();
    session.send(format!("/open {TITLE}\r")).unwrap();
    session.expect("Ask about the case").unwrap();
    session.send("/case delete\r").unwrap();
    session.expect("Delete unsealed case").unwrap();
    session.send("wrong title\r").unwrap();
    session.expect("Type the exact case title").unwrap();
    session.send(format!("\x15{TITLE}\r")).unwrap();
    session.expect("Enter signs the deletion").unwrap();
    session.send("\r").unwrap();
    session.expect("Case data deleted").unwrap();
    session.send("/cases deleted\r").unwrap();
    session
        .expect("Deleted cases · signed global audit")
        .unwrap();
    session.expect(TITLE).unwrap();
    session.expect("Reason: none").unwrap();
    session.send("\x1b").unwrap();
    session.expect("Find cases or type").unwrap();
    session.send("/quit\r").unwrap();
    session.expect("Exit IRMind?").unwrap();
    session.send("\r").unwrap();
}
