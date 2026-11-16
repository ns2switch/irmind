#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::{path::Path, process::Command, time::Duration};

#[path = "support/terminal_screen.rs"]
mod terminal_screen;

#[path = "support/demo_session.rs"]
mod demo_session;
use demo_session::DemoSession;

fn send_until(session: &mut DemoSession, input: &str, next_screen: &str) {
    session.send(input).unwrap();
    session.expect(next_screen).unwrap();
}

fn terminal_command(binary: &str, home: &Path) -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("stty cols 100 rows 32; exec \"$0\" --home \"$1\"")
        .arg(binary)
        .arg(home)
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1");
    command
}

#[test]
fn first_run_creates_file_keystore_without_leaving_the_tui() {
    let home = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_irmind");
    let mut session =
        DemoSession::spawn_sized(&terminal_command(binary, home.path()), 100, 32).unwrap();
    session.timeout = Duration::from_secs(45);
    session.expect("Welcome").unwrap();
    send_until(&mut session, "\r", "Choose a backend for the signing key:");
    send_until(
        &mut session,
        "2\r",
        "Choose a backend for the module secrets:",
    );
    send_until(&mut session, "2\r", "Create a passphrase");
    send_until(
        &mut session,
        "synthetic passphrase for PTY test\r",
        "Repeat the passphrase",
    );
    send_until(
        &mut session,
        "synthetic passphrase for PTY test\r",
        "Analyst public-key fingerprint:",
    );
    session.send("\r").unwrap();
    session.expect("First-run").unwrap();
    assert!(home.path().join("keystore.enc").exists());
    assert!(home.path().join("keystore.toml").exists());
    session.send("\x1b").unwrap();
    session.expect("No cases yet").unwrap();
    session.send("/quit\r\r").unwrap();
    drop(session);

    let mut unlock =
        DemoSession::spawn_sized(&terminal_command(binary, home.path()), 100, 32).unwrap();
    unlock.timeout = Duration::from_secs(45);
    unlock.expect("Unlock").unwrap();
    unlock.send("incorrect synthetic phrase\r").unwrap();
    unlock.expect("incorrect").unwrap();
    unlock.send("synthetic passphrase for PTY test\r").unwrap();
    unlock.expect("Analyst public-key fingerprint:").unwrap();
    unlock.send("\r").unwrap();
    unlock.expect("First-run").unwrap();
}
