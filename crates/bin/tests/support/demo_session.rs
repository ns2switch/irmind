use super::terminal_screen::TerminalScreen;
use std::{
    process::Command,
    time::{Duration, Instant},
};

pub(super) struct DemoSession {
    driver: Driver,
    screen: TerminalScreen,
    seen: Vec<u8>,
    timeout: Duration,
    sent: bool,
}
impl DemoSession {
    pub(super) fn spawn(command: Command) -> Result<Self, String> {
        Ok(Self {
            driver: Driver::spawn(command)?,
            screen: TerminalScreen::new(40, 120),
            seen: vec![],
            timeout: Duration::from_secs(20),
            sent: false,
        })
    }
    pub(super) fn expect(&mut self, needle: impl AsRef<str>) -> Result<Vec<u8>, String> {
        let needle = needle.as_ref();
        let started = Instant::now();
        let mut buffer = [0u8; 8192];
        loop {
            if !self.sent && self.screen.text().contains(needle) {
                return Ok(self.seen.clone());
            }
            if started.elapsed() > self.timeout {
                return Err(format!(
                    "no matching screen within {:?}: {needle}; screen: {}",
                    self.timeout,
                    self.screen.text()
                ));
            }
            let read = self.driver.read(&mut buffer)?;
            if read == 0 {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            if self.seen.len().saturating_add(read) > 8 * 1024 * 1024 {
                return Err("PTY output exceeded its test bound".into());
            }
            self.screen.feed(&buffer[..read]);
            self.seen.extend_from_slice(&buffer[..read]);
            for _ in buffer[..read]
                .windows(4)
                .filter(|bytes| *bytes == b"\x1b[6n")
            {
                self.driver.send(b"\x1b[1;1R")?;
            }
            self.sent = false;
        }
    }
    pub(super) fn send(&mut self, value: impl AsRef<str>) -> Result<(), String> {
        self.driver.send(value.as_ref().as_bytes())?;
        self.sent = true;
        Ok(())
    }
}

#[cfg(unix)]
struct Driver {
    session: expectrl::session::OsSession,
}
#[cfg(unix)]
impl Driver {
    fn spawn(command: Command) -> Result<Self, String> {
        Ok(Self {
            session: expectrl::session::OsSession::spawn(command)
                .map_err(|error| error.to_string())?,
        })
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        match self.session.try_read(buffer) {
            Ok(read) => Ok(read),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(error.to_string()),
        }
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        use std::io::Write as _;
        self.session
            .write_all(bytes)
            .map_err(|error| error.to_string())
    }
}

#[cfg(windows)]
struct Driver {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
    input: Box<dyn std::io::Write + Send>,
    output: std::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
}
#[cfg(windows)]
impl Driver {
    fn spawn(command: Command) -> Result<Self, String> {
        use std::io::Read as _;
        let mut builder = portable_pty::CommandBuilder::new(command.get_program());
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
        let pair = portable_pty::native_pty_system()
            .openpty(portable_pty::PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|error| error.to_string())?;
        let child = pair
            .slave
            .spawn_command(builder)
            .map_err(|error| error.to_string())?;
        let master = pair.master;
        let input = master.take_writer().map_err(|error| error.to_string())?;
        let mut reader = master
            .try_clone_reader()
            .map_err(|error| error.to_string())?;
        let (sender, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                let next = match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => Ok(buffer[..read].to_vec()),
                    Err(error) => Err(error.to_string()),
                };
                let failed = next.is_err();
                if sender.send(next).is_err() || failed {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            _master: master,
            input,
            output,
        })
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        match self.output.try_recv() {
            Ok(Ok(bytes)) => {
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Ok(Err(error)) => Err(error),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(0),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Err("PTY process ended".into()),
        }
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.input
            .write_all(bytes)
            .map_err(|error| error.to_string())
    }
}
#[cfg(windows)]
impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
