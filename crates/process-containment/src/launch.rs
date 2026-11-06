#[cfg(unix)]
use std::path::PathBuf;
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
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

#[derive(Clone, Copy, Debug, Default)]
pub struct WitnessStats {
    pub attempts: u64,
    pub elapsed: std::time::Duration,
}
pub(crate) struct Prepared {
    #[cfg(windows)]
    identity: crate::windows::process::Identity,
    #[cfg(windows)]
    session: crate::windows::network::Session,
    #[cfg(unix)]
    path: PathBuf,
    work: tempfile::TempDir,
}
#[cfg(windows)]
impl Prepared {
    pub(crate) fn probe_input(&self) -> io::Result<File> {
        File::open(self.work.path().join(crate::verification::CANARY))
    }
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
        let path = fs::canonicalize(path)?;
        #[cfg(windows)]
        let identity = crate::windows::process::Identity::new(&path, work.path())?;
        #[cfg(windows)]
        let session = crate::windows::network::Session::new()?;
        Ok(Self {
            inner: Arc::new(Prepared {
                #[cfg(windows)]
                identity,
                #[cfg(windows)]
                session,
                #[cfg(unix)]
                path,
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
        self.spawn_cancelable(input, mode, &|| false)
    }
    pub fn spawn_cancelable(
        &self,
        input: &File,
        mode: Mode,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Child> {
        if cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if !input.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "EVTX input is not a regular file",
            ));
        }
        #[cfg(unix)]
        {
            Ok(Child {
                native: native::spawn(&self.inner, input, mode)?,
                program: self.clone(),
            })
        }
        #[cfg(windows)]
        {
            let lease = self.inner.session.acquire(cancelled)?;
            let result = (|| {
                let stamp = self.inner.session.ensure(&self.inner, cancelled)?;
                let mut runtime = PreparedChild::new(&self.inner, false, [0, 0], Some(lease))?;
                self.inner.session.unchanged(stamp)?;
                runtime.stamp = Some(stamp);
                let native = native::spawn(&runtime, input, mode)?;
                Ok(Child {
                    native,
                    runtime,
                    program: self.clone(),
                    finished: false,
                })
            })();
            if result.is_err() {
                self.invalidate();
            }
            result
        }
    }
    pub fn invalidate(&self) {
        #[cfg(windows)]
        self.inner.session.invalidate();
    }
    pub fn witness_stats(&self) -> WitnessStats {
        #[cfg(windows)]
        {
            self.inner.session.stats()
        }
        #[cfg(not(windows))]
        {
            WitnessStats::default()
        }
    }
}

pub struct Child {
    native: native::Child,
    #[cfg(windows)]
    runtime: PreparedChild,
    program: Program,
    #[cfg(windows)]
    finished: bool,
}
impl Child {
    pub fn take_stdout(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.native.stdout()
    }
    pub fn take_stderr(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.native.stderr()
    }
    pub fn try_wait(&mut self) -> io::Result<Option<bool>> {
        let status = self.native.try_wait()?;
        #[cfg(windows)]
        if status == Some(true) {
            let stamp = self
                .runtime
                .stamp
                .ok_or_else(crate::witness_protocol::denied)?;
            if let Err(error) = self.program.inner.session.unchanged(stamp) {
                self.program.invalidate();
                return Err(error);
            }
            self.finished = true;
        }
        Ok(status)
    }
    pub fn exit_description(&mut self) -> io::Result<Option<String>> {
        self.native.exit_description()
    }
    pub fn terminate(&mut self) -> io::Result<()> {
        // Normal reader cleanup also calls terminate after a verified successful exit.
        // That is not a failed validation and must not invalidate the session witness.
        if self.try_wait()? != Some(true) {
            self.program.invalidate();
        }
        self.native.terminate()
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        let result = self.native.terminate();
        #[cfg(windows)]
        {
            if !self.finished {
                self.program.invalidate();
            }
            if result.is_err() {
                self.program.inner.session.poison();
            }
        }
        #[cfg(not(windows))]
        let _ = result;
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
    program: Arc<Prepared>,
    stamp: Option<crate::windows::network::ServiceStamp>,
    pub(crate) ticket: crate::witness_protocol::Ticket,
    _lease: Option<crate::windows::network::Lease>,
}
#[cfg(windows)]
impl PreparedChild {
    pub(crate) fn new(
        program: &Arc<Prepared>,
        witness: bool,
        ports: [u16; 2],
        lease: Option<crate::windows::network::Lease>,
    ) -> io::Result<Self> {
        let work = tempfile::Builder::new()
            .prefix("evtx-child-")
            .rand_bytes(32)
            .tempdir_in(program.work.path())?;
        initialize_work(work.path())?;
        program.identity.grant_runtime(work.path())?;
        let ticket = crate::witness_protocol::Ticket {
            witness,
            nonce: crate::windows::network::nonce()?,
            sid: program.identity.bytes().to_vec(),
            ports,
        };
        crate::windows::network::write_ticket(
            &work.path().join(crate::witness_protocol::TICKET),
            ticket.encode().as_bytes(),
            &program.identity,
        )?;
        Ok(Self {
            work,
            program: program.clone(),
            stamp: None,
            ticket,
            _lease: lease,
        })
    }
    pub(crate) fn path(&self) -> &Path {
        self.program.identity.executable()
    }
    pub(crate) fn work_dir(&self) -> &Path {
        self.work.path()
    }
    pub(crate) fn identity(&self) -> &crate::windows::process::Identity {
        &self.program.identity
    }
}
