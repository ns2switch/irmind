#![cfg(feature = "parser-json")]
#![allow(clippy::unwrap_used)]

use std::{process::Command, time::Duration};

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

fn run_demo(exit_keys: &str) {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let sentinel = real_home.path().join("config.toml");
    std::fs::write(&sentinel, "a deliberately invalid real configuration").unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_mins(1)));
    session.expect("ready:").unwrap();
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
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_secs(20)));
    let completed = session.expect("ready:");
    if completed.is_err() {
        let _ = session.send("/quit\r\r");
    }
    assert!(
        completed.is_ok(),
        "demo did not report ingest completion within 20 seconds: {completed:?}"
    );
    let initial = completed.unwrap();
    let initial = String::from_utf8_lossy(&initial);
    assert!(!initial.contains("Try"));
    assert!(!initial.contains("adds evidence"));
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
fn card_expands_from_the_text_box_with_control_o_and_slash_command() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_secs(20)));
    session.expect("ready:").unwrap();
    session.send("/demo hide\r/graph\r").unwrap();
    session.expect("Ctrl+O").unwrap();
    session.send("\x0f").unwrap();
    session.expect("records=").unwrap();
    session.send("\x0f").unwrap();
    session.expect("Ctrl+O").unwrap();
    session.send("/expand\r").unwrap();
    session.expect("records=").unwrap();
    session.send("/demo exit\r\r").unwrap();
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

#[test]
fn guided_demo_walks_ten_steps_in_a_terminal() {
    let real_home = tempfile::tempdir().unwrap();
    let demo_parent = tempfile::tempdir().unwrap();
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_secs(12)));
    session.expect("1/10").unwrap();
    eprintln!("guide step 1 visible");
    session.expect("ready:").unwrap();
    eprintln!("ingest complete");
    session.send("/demo next\r").unwrap();
    session.expect("2/10").unwrap();
    eprintln!("guide step 2 visible");
    session.send("/scope\r").unwrap();
    #[cfg(windows)]
    session.expect("Do: /demo next").unwrap();
    session.send("/demo next\r").unwrap();
    session.expect("3/10").unwrap();
    eprintln!("guide step 3 visible");
    session.send("/demo next\r").unwrap();
    session.expect("4/10").unwrap();
    eprintln!("guide step 4 visible");
    // Command names also occur in the input and guide before a query finishes.
    // Only its successful completion changes the guide's next instruction.
    for (command, next_instruction) in [
        ("/timeline", "search"),
        ("/search 203.0.113.77", "neighbors"),
        ("/neighbors ip 203.0.113.77", "complete."),
    ] {
        session.send(format!("{command}\r")).unwrap();
        let instruction = if cfg!(windows) {
            if next_instruction == "complete." {
                "Step complete.".to_owned()
            } else {
                format!("Do: /{next_instruction}")
            }
        } else {
            next_instruction.to_owned()
        };
        session.expect(instruction).unwrap();
        eprintln!("graph completed: {command}");
    }
    session.send("/demo next\r").unwrap();
    session.expect("5/10").unwrap();
    eprintln!("guide step 5 visible");
    session
        .send("What happened in this synthetic AWS IAM episode?\r")
        .unwrap();
    session.expect("points").unwrap();
    #[cfg(windows)]
    session.expect("Do: /demo next").unwrap();
    eprintln!("agent answered");
    session.send("/demo next\r").unwrap();
    session.expect("6/10").unwrap();
    eprintln!("guide step 6 visible");
    session.send("/approve \t\r").unwrap();
    session.expect("Approval:").unwrap();
    eprintln!("approval resolved");
    session.send("/demo next\r").unwrap();
    session.expect("7/10").unwrap();
    std::thread::sleep(Duration::from_millis(250));
    eprintln!("guide step 7 visible");
    session.send("/confirm \t\r").unwrap();
    #[cfg(windows)]
    session.expect("Do: /demo next").unwrap();
    session.send("/demo next\r").unwrap();
    session.expect("8/10").unwrap();
    eprintln!("finding confirmed");
    eprintln!("guide step 8 visible");
    session.send("/demo check\r").unwrap();
    #[cfg(windows)]
    session.expect("Do: /demo next").unwrap();
    session.send("/demo next\r").unwrap();
    // Reaching step 9 proves that /demo check ran: next cannot advance until
    // the guide records the comparison. Text within the result card can be
    // repainted before the guide counter on Windows ConPTY.
    session.expect("9/10").unwrap();
    eprintln!("check complete");
    eprintln!("guide step 9 visible");
    complete_demo_custody(&mut session);
    session.send("/demo exit\r\r").unwrap();
    session.expect("Demo data deleted").unwrap();
    assert_eq!(std::fs::read_dir(real_home.path()).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(demo_parent.path()).unwrap().count(), 0);
}

fn complete_demo_custody(session: &mut DemoSession) {
    session.send("/verify\r").unwrap();
    session.expect("Verified").unwrap();
    session.send("/seal\r").unwrap();
    expect_custody_confirmation(session);
    session.send("2\r").unwrap();
    session.expect("Seal:").unwrap();
    eprintln!("case sealed");
    session.send("/export\r").unwrap();
    expect_custody_confirmation(session);
    session.send("2\r").unwrap();
    session.expect("Exported").unwrap();
    eprintln!("case exported");
    session.send("/verify-export\r").unwrap();
    session.expect("Verify export:").unwrap();
    eprintln!("export verified");
    std::thread::sleep(Duration::from_millis(250));
    session.send("/demo next\r").unwrap();
    session.expect("10/10").unwrap();
    eprintln!("guide step 10 visible");
}

fn expect_custody_confirmation(session: &mut DemoSession) {
    #[cfg(windows)]
    session.expect("1. Cancel  2. Confirm").unwrap();
    #[cfg(unix)]
    session.expect("Confirm").unwrap();
}

#[test]
fn control_c_cleans_the_demo_from_every_guide_step() {
    for step in 1..=10 {
        let real_home = tempfile::tempdir().unwrap();
        let demo_parent = tempfile::tempdir().unwrap();
        let mut session =
            DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
        session.set_expect_timeout(Some(Duration::from_secs(20)));
        session.expect("ready:").unwrap();
        for next in 2..=step {
            session.send("/demo skip\r").unwrap();
            session.expect(format!("{next}/10")).unwrap();
        }
        session.send("\x03\r").unwrap();
        #[cfg(unix)]
        let completion = session.expect("Demo data deleted").unwrap();
        #[cfg(windows)]
        session.expect("Demo data deleted").unwrap();
        #[cfg(unix)]
        assert!(
            completion
                .as_slice()
                .windows(8)
                .any(|bytes| bytes == b"\x1b[?1049l"),
            "leaving the demo must restore the terminal's main screen"
        );
        assert_eq!(std::fs::read_dir(real_home.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(demo_parent.path()).unwrap().count(), 0);
    }
}
