#![cfg(windows)]
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
pub(super) struct Handle(OwnedHandle);
impl Handle {
    pub(super) fn new(raw: HANDLE) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("invalid native helper handle"));
        }
        // SAFETY: callers transfer one newly created, valid owned kernel handle. OwnedHandle closes it once.
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(raw.cast()) }))
    }
    pub(super) fn raw(&self) -> HANDLE {
        self.0.as_raw_handle().cast()
    }
    pub(super) fn into_file(self) -> File {
        File::from(self.0)
    }
}
