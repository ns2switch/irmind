#![cfg(feature = "parser-json")]
#![allow(clippy::unwrap_used)]

use expectrl::{Expect as _, Session};
use std::{process::Command, time::Duration};

fn demo_command(real_home: &std::path::Path, demo_parent: &std::path::Path) -> Command {
    #[cfg(unix)]
    let mut command = {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("stty cols 100 rows 32; exec \"$0\" --home \"$1\" demo --scripted")
            .arg(env!("CARGO_BIN_EXE_irmind"))
            .arg(real_home);
        command
    };
    #[cfg(windows)]
    let mut command = {
        let mut command = Command::new(env!("CARGO_BIN_EXE_irmind"));
        command
            .arg("--home")
            .arg(real_home)
            .arg("demo")
            .arg("--scripted");
        command
    };
    command
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1")
        .env("TMPDIR", demo_parent)
        .env("TMP", demo_parent)
        .env("TEMP", demo_parent)
        .env("HTTP_PROXY", "")
        .env("HTTPS_PROXY", "");
    command
}

fn run_demo(exit_keys: &str) {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let sentinel = real_home.path().join("config.toml");
    std::fs::write(&sentinel, "a deliberately invalid real configuration").unwrap();
    let mut session = Session::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_mins(1)));
    session.set_expect_lazy(cfg!(windows));
    session.expect("Ingested").unwrap();
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
fn demo_ingest_completion_is_visible_and_followup_command_responds() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session = Session::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_secs(20)));
    session.set_expect_lazy(cfg!(windows));
    let completed = session.expect("Ingested");
    if completed.is_err() {
        let _ = session.send("/quit\r\r");
    }
    assert!(
        completed.is_ok(),
        "demo did not report ingest completion within 20 seconds: {completed:?}"
    );
    session.expect("parser-json").unwrap();
    session.expect("90%").unwrap();
    session.send("/help\r").unwrap();
    session.expect("Commands").unwrap();
    session.send("\x1b/quit\r\r").unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_eq!(std::fs::read_dir(real_home.path()).unwrap().count(), 0);
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
