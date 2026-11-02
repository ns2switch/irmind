#![cfg(feature = "parser-json")]
#![allow(clippy::unwrap_used)]

use std::{process::Command, time::Duration};

#[cfg(unix)]
use expectrl::{Expect as _, Session as DemoSession};

#[cfg(windows)]
mod windows_pty {
    use super::{Command, Duration};
    use portable_pty::{CommandBuilder, PtySize, PtySystem as _, native_pty_system};
    use std::{
        io::{Read as _, Write as _},
        sync::mpsc::{self, Receiver, RecvTimeoutError},
        time::Instant,
    };

    pub(super) struct DemoSession {
        child: Box<dyn portable_pty::Child + Send + Sync>,
        input: Box<dyn std::io::Write + Send>,
        output: Receiver<Result<Vec<u8>, String>>,
        seen: Vec<u8>,
        cursor: usize,
        answered_cursor_queries: usize,
        timeout: Duration,
    }

    impl DemoSession {
        pub(super) fn spawn(command: Command) -> Result<Self, String> {
            let mut builder = CommandBuilder::new(command.get_program());
            builder.args(command.get_args());
            if let Some(directory) = command.get_current_dir() {
                builder.cwd(directory);
            }
            for (name, value) in command.get_envs() {
                if let Some(value) = value {
                    builder.env(name, value);
                } else {
                    builder.env_remove(name);
                }
            }
            let pair = native_pty_system()
                .openpty(PtySize {
                    rows: 32,
                    cols: 100,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|error| error.to_string())?;
            let child = pair
                .slave
                .spawn_command(builder)
                .map_err(|error| error.to_string())?;
            let input = pair
                .master
                .take_writer()
                .map_err(|error| error.to_string())?;
            let mut reader = pair
                .master
                .try_clone_reader()
                .map_err(|error| error.to_string())?;
            let (sender, output) = mpsc::channel();
            std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                loop {
                    let read = match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string()));
                            break;
                        }
                    };
                    if sender.send(Ok(buffer[..read].to_vec())).is_err() {
                        break;
                    }
                }
            });
            Ok(Self {
                child,
                input,
                output,
                seen: Vec::new(),
                cursor: 0,
                answered_cursor_queries: 0,
                timeout: Duration::from_secs(10),
            })
        }

        pub(super) fn set_expect_timeout(&mut self, timeout: Option<Duration>) {
            self.timeout = timeout.unwrap_or(Duration::from_secs(60));
        }

        pub(super) fn expect(&mut self, needle: &str) -> Result<(), String> {
            let started = Instant::now();
            loop {
                if let Some(offset) = self.seen[self.cursor..]
                    .windows(needle.len())
                    .position(|part| part == needle.as_bytes())
                {
                    self.cursor += offset + needle.len();
                    return Ok(());
                }
                if started.elapsed() >= self.timeout {
                    return Err(format!(
                        "timed out after {}s waiting for {needle}; read {} PTY bytes; first bytes: {:?}",
                        self.timeout.as_secs(),
                        self.seen.len(),
                        String::from_utf8_lossy(&self.seen[..self.seen.len().min(512)])
                    ));
                }
                match self.output.recv_timeout(Duration::from_millis(25)) {
                    Ok(Ok(chunk)) => {
                        self.seen.extend_from_slice(&chunk);
                        self.answer_cursor_queries()?;
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(format!("PTY ended while waiting for {needle}"));
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
        }

        pub(super) fn send(&mut self, value: &str) -> Result<(), String> {
            self.input
                .write_all(value.as_bytes())
                .map_err(|error| error.to_string())
        }

        fn answer_cursor_queries(&mut self) -> Result<(), String> {
            let count = self
                .seen
                .windows(4)
                .filter(|bytes| *bytes == b"\x1b[6n")
                .count();
            for _ in self.answered_cursor_queries..count {
                self.input
                    .write_all(b"\x1b[1;1R")
                    .map_err(|error| error.to_string())?;
            }
            self.answered_cursor_queries = count;
            Ok(())
        }
    }

    impl Drop for DemoSession {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(windows)]
use windows_pty::DemoSession;

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
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_mins(1)));
    #[cfg(unix)]
    session.set_expect_lazy(false);
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
    let mut session =
        DemoSession::spawn(demo_command(real_home.path(), demo_parent.path())).unwrap();
    session.set_expect_timeout(Some(Duration::from_secs(20)));
    #[cfg(unix)]
    session.set_expect_lazy(false);
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
