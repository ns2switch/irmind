#![cfg(all(unix, feature = "parser-json"))]
#![allow(clippy::unwrap_used)]

use expectrl::{Expect as _, Session};
use std::{process::Command, time::Duration};

fn run_demo(exit_keys: &str) {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let sentinel = real_home.path().join("config.toml");
    std::fs::write(&sentinel, "a deliberately invalid real configuration").unwrap();
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("stty cols 100 rows 32; exec \"$0\" --home \"$1\" demo --scripted")
        .arg(env!("CARGO_BIN_EXE_irmind"))
        .arg(real_home.path())
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1")
        .env("TMPDIR", demo_parent.path())
        .env("HTTP_PROXY", "")
        .env("HTTPS_PROXY", "");
    let mut session = Session::spawn(command).unwrap();
    session.set_expect_timeout(Some(Duration::from_mins(1)));
    session.expect("HuntEval").unwrap();
    session.send(exit_keys).unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_eq!(
        std::fs::read_to_string(sentinel).unwrap(),
        "a deliberately invalid real configuration"
    );
    assert_eq!(std::fs::read_dir(real_home.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read_dir(demo_parent.path()).unwrap().count(), 0);
}

#[test]
fn demo_is_isolated_and_removed_after_exit() {
    run_demo("/quit\r\r");
}

#[test]
fn demo_is_removed_after_control_c_confirmation() {
    run_demo("\x03\r");
}
