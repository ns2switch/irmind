#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use expectrl::{Expect as _, Session};
use std::{path::Path, process::Command, thread, time::Duration};

fn wait_for_file(path: &Path) -> bool {
    for _ in 0..100 {
        if path.is_file() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
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
    let mut session = Session::spawn(terminal_command(binary, home.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_secs(45)));
    session.expect("Welcome").unwrap();
    session.send("\r").unwrap();
    thread::sleep(Duration::from_millis(150));
    session.send("\x1b[B").unwrap();
    thread::sleep(Duration::from_millis(50));
    session.send("\r").unwrap();
    thread::sleep(Duration::from_millis(150));
    session.send("\x1b[B").unwrap();
    thread::sleep(Duration::from_millis(50));
    session.send("\r").unwrap();
    thread::sleep(Duration::from_millis(150));
    session.send("synthetic passphrase for PTY test\r").unwrap();
    thread::sleep(Duration::from_millis(150));
    session.send("synthetic passphrase for PTY test\r").unwrap();
    assert!(wait_for_file(&home.path().join("keystore.toml")));
    session.send("\r").unwrap();
    session.expect("First-run").unwrap();
    assert!(home.path().join("keystore.enc").exists());
    assert!(home.path().join("keystore.toml").exists());
    session.send("q").unwrap();
    drop(session);

    let mut unlock = Session::spawn(terminal_command(binary, home.path())).unwrap();
    unlock.set_expect_timeout(Some(Duration::from_secs(45)));
    unlock.expect("Unlock").unwrap();
    unlock.send("incorrect synthetic phrase\r").unwrap();
    unlock.expect("incorrect").unwrap();
    unlock.send("synthetic passphrase for PTY test\r").unwrap();
    thread::sleep(Duration::from_secs(2));
    unlock.send("\r").unwrap();
    unlock.expect("First-run").unwrap();
}
