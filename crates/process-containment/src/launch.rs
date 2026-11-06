use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
use crate::windows::process as native;
#[cfg(unix)]
use unix as native;

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Probe,
    Decode,
}
impl Mode {
    pub(crate) fn arg(self) -> &'static str {
        match self {
            Self::Probe => "--probe-v1",
            Self::Decode => "--protocol-v1",
        }
    }
}

pub(crate) struct Prepared {
    path: PathBuf,
    work: tempfile::TempDir,
}
#[derive(Clone)]
pub struct Program {
    inner: Arc<Prepared>,
}
impl Program {
    pub fn new(path: &Path, data_root: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "EVTX helper must be a regular executable",
            ));
        }
        let work = tempfile::Builder::new()
            .prefix("evtx-runtime-")
            .rand_bytes(16)
            .tempdir_in(fs::canonicalize(data_root)?)?;
        initialize_work(work.path())?;
        Ok(Self {
            inner: Arc::new(Prepared {
                path: fs::canonicalize(path)?,
                work,
            }),
        })
    }
    pub fn probe(&self) -> io::Result<Child> {
        self.spawn(
            &File::open(self.inner.work.path().join(crate::verification::CANARY))?,
            Mode::Probe,
        )
    }
    pub fn spawn(&self, input: &File, mode: Mode) -> io::Result<Child> {
        if !input.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "EVTX input is not a regular file",
            ));
        }
        #[cfg(unix)]
        let native = native::spawn(&self.inner, input, mode)?;
        #[cfg(windows)]
        let runtime = PreparedChild::new(&self.inner)?;
        #[cfg(windows)]
        let native = native::spawn(&runtime, input, mode)?;
        Ok(Child {
            native,
            #[cfg(windows)]
            _runtime: runtime,
            _program: self.clone(),
        })
    }
}

pub struct Child {
    native: native::Child,
    #[cfg(windows)]
    _runtime: PreparedChild,
    _program: Program,
}
impl Child {
    pub fn take_stdout(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.native.stdout()
    }
    pub fn take_stderr(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.native.stderr()
    }
    pub fn try_wait(&mut self) -> io::Result<Option<bool>> {
        self.native.try_wait()
    }
    pub fn exit_description(&mut self) -> io::Result<Option<String>> {
        self.native.exit_description()
    }
    pub fn terminate(&mut self) -> io::Result<()> {
        self.native.terminate()
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.native.terminate();
    }
}

fn initialize_work(path: &Path) -> io::Result<()> {
    private(path)?;
    let canary = path.join(crate::verification::CANARY);
    fs::write(&canary, b"synthetic containment canary")?;
    private(&canary)
}
fn private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }),
        )
    }
    #[cfg(windows)]
    {
        crate::filesystem::private_windows(path)
    }
}

#[cfg(windows)]
pub(crate) struct PreparedChild {
    work: tempfile::TempDir,
    identity: crate::windows::process::Identity,
}
#[cfg(windows)]
impl PreparedChild {
    fn new(program: &Prepared) -> io::Result<Self> {
        let work = tempfile::Builder::new()
            .prefix("evtx-child-")
            .rand_bytes(32)
            .tempdir_in(program.work.path())?;
        initialize_work(work.path())?;
        let identity = crate::windows::process::Identity::new(&program.path, work.path())?;
        Ok(Self { work, identity })
    }
    pub(crate) fn path(&self) -> &Path {
        self.identity.executable()
    }
    pub(crate) fn work_dir(&self) -> &Path {
        self.work.path()
    }
    pub(crate) fn identity(&self) -> &crate::windows::process::Identity {
        &self.identity
    }
}
