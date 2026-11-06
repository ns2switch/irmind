#![cfg(windows)]
use super::error;
use std::{
    fs, io,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::Security::{FreeSid, GetLengthSid, PSID};

pub(crate) struct Identity {
    words: Vec<usize>,
    length: usize,
    executable: PathBuf,
    profile: super::profile::Profile,
}
struct Sid(PSID);
impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: CreateAppContainerProfile allocated this SID; this guard frees it once.
        unsafe { FreeSid(self.0) };
    }
}
impl Identity {
    pub(crate) fn new(source: &Path, work: &Path) -> io::Result<Self> {
        let name = format!(
            "irmind-evtx-{}",
            work.file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(|| error("identity-name"))?
        );
        let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let (profile, raw) = super::profile::Profile::create(name)?;
        let sid = Sid(raw);
        // SAFETY: the API returned a complete, valid SID, retained by the guard.
        let length = unsafe { GetLengthSid(sid.0) } as usize;
        if !(8..=256).contains(&length) {
            return Err(error("SID-length"));
        }
        let mut words = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: source has length initialized bytes and destination is aligned with at least length bytes; allocations do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(sid.0.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), length);
        };
        let executable = work.join("irmind-evtx.exe");
        fs::copy(source, &executable)?;
        let identity = Self {
            words,
            length,
            executable,
            profile,
        };
        super::super::filesystem::helper_read_execute(work, identity.bytes())?;
        super::super::filesystem::helper_read_execute(&identity.executable, identity.bytes())?;
        Ok(identity)
    }
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }
    pub(super) fn local_data(&self) -> &Path {
        self.profile.local_data()
    }
    pub(crate) fn grant_read(&self, path: &Path) -> io::Result<()> {
        super::super::filesystem::helper_read_only(path, self.bytes())
    }
    pub(crate) fn grant_runtime(&self, path: &Path) -> io::Result<()> {
        super::super::filesystem::helper_read_execute(path, self.bytes())
    }
    pub(super) fn raw(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: constructor bounds length by the initialized allocation; this immutable slice cannot outlive self.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.length) }
    }
}
