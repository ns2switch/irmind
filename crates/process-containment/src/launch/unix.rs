use super::{File, Mode, Prepared, Read, io};
use std::process::{Command, Stdio};

pub(super) struct Child(std::process::Child);
pub(super) fn spawn(program: &Prepared, input: &File, mode: Mode) -> io::Result<Child> {
    if rustix::fs::fcntl_getfl(input)
        .map_err(io::Error::from)?
        .contains(rustix::fs::OFlags::WRONLY)
        || rustix::fs::fcntl_getfl(input)
            .map_err(io::Error::from)?
            .contains(rustix::fs::OFlags::RDWR)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "EVTX requires a read-only input handle",
        ));
    }
    #[cfg(target_os = "linux")]
    let mut command = command(program);
    #[cfg(target_os = "macos")]
    let mut command = command(program)?;
    command
        .arg(mode.arg())
        .current_dir(program.work.path())
        .env_clear()
        .stdin(Stdio::from(input.try_clone()?))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.spawn().map(Child)
}

#[cfg(target_os = "linux")]
fn command(program: &Prepared) -> Command {
    Command::new(&program.path)
}

#[cfg(target_os = "macos")]
fn command(program: &Prepared) -> io::Result<Command> {
    let path = program
        .path
        .to_str()
        .filter(|v| !v.contains(['\n', '\r', '\0']))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid helper executable path",
            )
        })?;
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    let profile = format!(
        r#"(version 1)(deny default)(allow process-exec (literal "{escaped}"))(deny process-fork)(allow sysctl-read)(allow file-read-metadata)(allow file-read-data (subpath "/System/Library") (subpath "/usr/lib") (literal "{escaped}") (literal "/dev/urandom") (literal "/dev/null"))"#
    );
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.args(["-p", &profile, "--"]).arg(&program.path);
    Ok(command)
}

impl Child {
    pub(super) fn stdout(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.0
            .stdout
            .take()
            .map(|v| Box::new(v) as Box<dyn Read + Send>)
            .ok_or_else(|| io::Error::other("missing helper stdout"))
    }
    pub(super) fn stderr(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.0
            .stderr
            .take()
            .map(|v| Box::new(v) as Box<dyn Read + Send>)
            .ok_or_else(|| io::Error::other("missing helper stderr"))
    }
    pub(super) fn try_wait(&mut self) -> io::Result<Option<bool>> {
        Ok(self.0.try_wait()?.map(|status| status.success()))
    }
    pub(super) fn terminate(&mut self) -> io::Result<()> {
        if self.0.try_wait()?.is_none() {
            self.0.kill()?;
        }
        self.0.wait()?;
        Ok(())
    }
}
