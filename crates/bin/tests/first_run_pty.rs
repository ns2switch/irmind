#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use expectrl::{Expect as _, Session, session::OsSession};
use std::{io::ErrorKind, path::Path, process::Command, thread, time::Duration};

fn drain_output(session: &mut OsSession) {
    let mut output = [0_u8; 8192];
    loop {
        match session.try_read(&mut output) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::WouldBlock, "PTY read: {error}");
                break;
            }
        }
    }
}

fn send_and_drain(session: &mut OsSession, input: &str) {
    session.send(input).unwrap();
    for _ in 0..10 {
        drain_output(session);
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_file(session: &mut OsSession, path: &Path) -> bool {
    for _ in 0..900 {
        drain_output(session);
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
    send_and_drain(&mut session, "\r");
    send_and_drain(&mut session, "\x1b[B");
    send_and_drain(&mut session, "\r");
    send_and_drain(&mut session, "\x1b[B");
    send_and_drain(&mut session, "\r");
    send_and_drain(&mut session, "synthetic passphrase for PTY test\r");
    send_and_drain(&mut session, "synthetic passphrase for PTY test\r");
    assert!(wait_for_file(
        &mut session,
        &home.path().join("keystore.toml")
    ));
    session.send("\r").unwrap();
    session.expect("First-run").unwrap();
    assert!(home.path().join("keystore.enc").exists());
    assert!(home.path().join("keystore.toml").exists());
    session.send("\x1b").unwrap();
    session.send("/quit\r\r").unwrap();
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
