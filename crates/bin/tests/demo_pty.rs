#![cfg(feature = "parser-json")]
#![allow(clippy::unwrap_used)]

use std::process::Command;

#[path = "support/terminal_screen.rs"]
mod terminal_screen;

#[path = "support/demo_session.rs"]
mod demo_session;
use demo_session::DemoSession;

fn demo_command(real_home: &std::path::Path, demo_parent: &std::path::Path) -> Command {
    #[cfg(unix)]
    let mut command = {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("stty cols 120 rows 40; exec \"$0\" --home \"$1\" demo --scripted --presentation-speed 50")
            .arg(env!("CARGO_BIN_EXE_irmind"))
            .arg(real_home);
        command
    };
    #[cfg(windows)]
    let mut command = {
        // Give the TUI console standard handles rather than the invalid
        // handles on portable-pty's initial ConPTY process. Pass arguments
        // separately so CommandBuilder quotes paths with spaces correctly.
        let mut command = Command::new("cmd.exe");
        command
            .arg("/d")
            .arg("/c")
            .arg("chcp")
            .arg("65001")
            .arg(">nul")
            .arg("&&")
            .arg(env!("CARGO_BIN_EXE_irmind"))
            .arg("--home")
            .arg(real_home)
            .arg("demo")
            .arg("--scripted")
            .arg("--presentation-speed")
            .arg("50")
            .arg("<CONIN$")
            .arg(">CONOUT$")
            .arg("2>&1");
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

#[test]
fn automatic_presentation_reaches_signed_evidence_and_exits_cleanly() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.expect("Step 1 of 10").unwrap();
    session.expect("Step 2 of 10").unwrap();
    session.expect("Step 3 of 10").unwrap();
    session.expect("Evidence ready:").unwrap();
    session.expect("90% confidence").unwrap();
    session.send("\x1b").unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_eq!(std::fs::read_dir(real_home.path()).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(demo_parent.path()).unwrap().count(), 0);
}

fn assert_deleted(real_home: &std::path::Path, demo_parent: &std::path::Path) {
    assert_eq!(std::fs::read_dir(real_home).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(demo_parent).unwrap().count(), 0);
}

fn expect_step(session: &mut DemoSession, step: usize) {
    let script: serde_json::Value =
        serde_json::from_str(include_str!("../../tui/assets/demo-presentation.en.json")).unwrap();
    let title = script["steps"][step - 1]["title"].as_str().unwrap();
    session
        .expect(format!("Step {step} of 10 · {title}"))
        .unwrap();
}

fn reach_final(session: &mut DemoSession) {
    for step in 1..=10 {
        expect_step(session, step);
        eprintln!("presentation step {step} visible");
    }
}

#[test]
fn automatic_presentation_completes_real_queries_approval_and_custody() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    reach_final(&mut session);
    session
        .expect("Explore this demo case (sealed, read-only)")
        .unwrap();
    session.send("\x1b").unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_deleted(real_home.path(), demo_parent.path());
}

#[test]
fn manual_presentation_visits_every_narration_and_can_go_back() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.expect("Step 1 of 10").unwrap();
    session.send(" ").unwrap();
    session.expect("Paused").unwrap();
    for step in 2..=10 {
        session.send("\r").unwrap();
        expect_step(&mut session, step);
    }
    session.send("\x7f").unwrap();
    session.expect("Step 9 of 10").unwrap();
    session.send("\r").unwrap();
    session.expect("Step 10 of 10").unwrap();
    session.send("\x1b").unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_deleted(real_home.path(), demo_parent.path());
}

#[test]
fn ingest_completion_is_visible_and_next_action_changes_the_screen() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.expect("Evidence ready:").unwrap();
    session.expect("parser-json").unwrap();
    session.expect("90% confidence").unwrap();
    session.expect("Step 4 of 10").unwrap();
    session.expect("/timeline").unwrap();
    session.expect("Step 5 of 10").unwrap();
    session.send("\x1b").unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_deleted(real_home.path(), demo_parent.path());
}

#[test]
fn card_expands_from_the_text_box_with_control_o_and_slash_command() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    reach_final(&mut session);
    session.send("\r").unwrap();
    session.expect("Demo exploration").unwrap();
    session.send("/graph\r").unwrap();
    session.expect("Ctrl+O").unwrap();
    session.send("\x0f").unwrap();
    session.expect("records=").unwrap();
    session.send("\x0f").unwrap();
    session.expect("Ctrl+O").unwrap();
    session.send("/expand\r").unwrap();
    session.expect("records=").unwrap();
    session.send("/demo exit\r\r").unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_deleted(real_home.path(), demo_parent.path());
}

#[test]
fn escape_and_control_c_leave_real_configuration_untouched() {
    for exit in ["\x1b", "\x03"] {
        let real_home = tempfile::tempdir().unwrap();
        let demo_parent = tempfile::tempdir().unwrap();
        let sentinel = real_home.path().join("config.toml");
        std::fs::write(&sentinel, "a deliberately invalid real configuration").unwrap();
        let mut session =
            DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
        session.expect("Step 3 of 10").unwrap();
        session.send(exit).unwrap();
        session.expect("Demo data deleted").unwrap();
        assert_eq!(
            std::fs::read_to_string(sentinel).unwrap(),
            "a deliberately invalid real configuration"
        );
        assert_eq!(std::fs::read_dir(real_home.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(demo_parent.path()).unwrap().count(), 0);
    }
}

fn cancel_at_every_step(exit_key: &str) {
    for target in 1..=10 {
        let real_home = tempfile::tempdir().unwrap();
        let demo_parent = tempfile::tempdir().unwrap();
        let mut session =
            DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
        for step in 1..=target {
            expect_step(&mut session, step);
        }
        session.send(exit_key).unwrap();
        let output = session.expect("Demo data deleted").unwrap();
        assert!(
            output.windows(8).any(|bytes| bytes == b"\x1b[?1049l"),
            "terminal main screen was not restored"
        );
        assert_deleted(real_home.path(), demo_parent.path());
    }
}

#[test]
fn control_c_cleans_and_restores_the_terminal_from_every_presentation_step() {
    cancel_at_every_step("\x03");
}

#[test]
fn escape_cleans_and_restores_the_terminal_from_every_presentation_step() {
    cancel_at_every_step("\x1b");
}
