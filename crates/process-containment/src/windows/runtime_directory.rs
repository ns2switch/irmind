#![cfg(windows)]
//! Validate the non-inheritable working-directory handle created by Windows.
use std::{fs::File, io, os::windows::fs::OpenOptionsExt as _};
use windows_sys::{
    Wdk::Foundation::{NtQueryObject, ObjectBasicInformation},
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_TRAVERSE, GetFileInformationByHandle, SYNCHRONIZE,
        },
        System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION,
    },
};

pub(super) struct RuntimeDirectory {
    _file: File,
    identity: (u32, u32, u32),
}
impl RuntimeDirectory {
    pub(super) fn open() -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle as _;
        // The broker explicitly sets this private directory; request metadata only.
        let file = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(".")?;
        let identity = directory_identity(file.as_raw_handle()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid EVTX runtime directory",
            )
        })?;
        Ok(Self {
            _file: file,
            identity,
        })
    }
    pub(super) fn matches(&self, handle: HANDLE) -> bool {
        metadata_only(handle) && directory_identity(handle) == Some(self.identity)
    }
}

fn metadata_only(handle: HANDLE) -> bool {
    let mut info = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let mut returned = 0;
    let Ok(size) = u32::try_from(std::mem::size_of_val(&info)) else {
        return false;
    };
    // SAFETY: the OS validates the borrowed handle; the aligned initialized output
    // and exact byte length match ObjectBasicInformation. No pointer escapes.
    let status = unsafe {
        NtQueryObject(
            handle,
            ObjectBasicInformation,
            (&raw mut info).cast(),
            size,
            &raw mut returned,
        )
    };
    status >= 0
        && returned as usize == std::mem::size_of_val(&info)
        && info.GrantedAccess & !(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE) == 0
}

fn directory_identity(handle: HANDLE) -> Option<(u32, u32, u32)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the OS validates the borrowed disk handle; output is initialized,
    // correctly aligned and lives throughout the synchronous query.
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return None;
    }
    Some((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ADD_FILE;

    #[test]
    fn only_metadata_access_to_the_exact_runtime_directory_is_accepted() {
        let runtime = RuntimeDirectory::open().unwrap();
        let same = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(".")
            .unwrap();
        assert!(runtime.matches(same.as_raw_handle()));
        let other = tempfile::tempdir().unwrap();
        let foreign = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(other.path())
            .unwrap();
        assert!(!runtime.matches(foreign.as_raw_handle()));
        let write = std::fs::OpenOptions::new()
            .access_mode(FILE_ADD_FILE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(".")
            .unwrap();
        assert!(!runtime.matches(write.as_raw_handle()));
        let regular = tempfile::tempfile().unwrap();
        assert!(!runtime.matches(regular.as_raw_handle()));
    }
}
