#![cfg(windows)]
use super::{Handle, error};
use std::{fs::File, io, os::windows::io::AsRawHandle as _, ptr};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, HANDLE_FLAG_INHERIT, SetHandleInformation},
    Security::SECURITY_ATTRIBUTES,
    System::{Pipes::CreatePipe, Threading::GetCurrentProcess},
};
pub(super) struct Pipes {
    pub(super) input: Handle,
    pub(super) output_read: Handle,
    pub(super) output_write: Handle,
    pub(super) error_read: Handle,
    pub(super) error_write: Handle,
}
impl Pipes {
    pub(super) fn new(input: &File) -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: borrowed pseudo-handles and input handle are live; duplicate is a new owned, inheritable read-only handle.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                input.as_raw_handle().cast(),
                GetCurrentProcess(),
                &raw mut raw,
                windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
                1,
                0,
            )
        } == 0
        {
            return Err(error("input-duplication"));
        }
        let input = Handle::new(raw)?;
        let (output_read, output_write) = pipe()?;
        let (error_read, error_write) = pipe()?;
        Ok(Self {
            input,
            output_read,
            output_write,
            error_read,
            error_write,
        })
    }
}
fn pipe() -> io::Result<(Handle, Handle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| error("pipe-size"))?,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: valid out pointers and initialized security attributes; handles become owned immediately below.
    if unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) } == 0 {
        return Err(error("output-pipe"));
    }
    let read = Handle::new(read)?;
    let write = Handle::new(write)?;
    // SAFETY: live parent read end; clear inheritance before child creation.
    if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(error("pipe-inheritance"));
    }
    Ok((read, write))
}
