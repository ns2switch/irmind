#![cfg(windows)]
//! Validate non-inheritable runtime handles and read-only aliases of the inherited evidence.
use std::{fs::File, io, os::windows::fs::OpenOptionsExt as _};
use windows_sys::{
    Wdk::Foundation::{NtQueryObject, ObjectBasicInformation},
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
            FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, GetFileInformationByHandle, SYNCHRONIZE,
        },
        System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION,
    },
};

pub(super) struct RuntimeDirectory {
    _file: File,
    identity: (u32, u32, u32),
    evidence: (u32, u32, u32),
}
impl RuntimeDirectory {
    pub(super) fn open(evidence: &File) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle as _;
        // The broker explicitly sets this private directory; request metadata only.
        let file = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(".")?;
        let identity = file_identity(file.as_raw_handle(), true).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid EVTX runtime directory",
            )
        })?;
        Ok(Self {
            _file: file,
            identity,
            evidence: file_identity(evidence.as_raw_handle(), false)
                .ok_or_else(|| io::Error::other("invalid EVTX evidence handle"))?,
        })
    }
    pub(super) fn matches(&self, handle: HANDLE) -> bool {
        let Some(access) = access_mask(handle) else {
            return false;
        };
        (access & !(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) == 0
            && file_identity(handle, true) == Some(self.identity))
            || (access & !FILE_GENERIC_READ == 0
                && file_identity(handle, false) == Some(self.evidence))
    }
    pub(super) fn diagnostic(&self, handle: HANDLE) -> String {
        format!(
            "access={:#x}, runtime_directory={}, evidence={}",
            access_mask(handle).unwrap_or(u32::MAX),
            file_identity(handle, true) == Some(self.identity),
            file_identity(handle, false) == Some(self.evidence)
        )
    }
}

fn access_mask(handle: HANDLE) -> Option<u32> {
    let mut info = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let mut returned = 0;
    let Ok(size) = u32::try_from(std::mem::size_of_val(&info)) else {
        return None;
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
    (status >= 0 && returned as usize == std::mem::size_of_val(&info)).then_some(info.GrantedAccess)
}

fn file_identity(handle: HANDLE, directory: bool) -> Option<(u32, u32, u32)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the OS validates the borrowed disk handle; output is initialized,
    // correctly aligned and lives throughout the synchronous query.
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
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
    fn only_read_only_aliases_of_the_runtime_directory_or_evidence_are_accepted() {
        let input = tempfile::NamedTempFile::new().unwrap();
        let evidence = File::open(input.path()).unwrap();
        let runtime = RuntimeDirectory::open(&evidence).unwrap();
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
        let regular = tempfile::NamedTempFile::new().unwrap();
        let foreign_read = File::open(regular.path()).unwrap();
        assert!(!runtime.matches(foreign_read.as_raw_handle()));
        let alias = File::open(input.path()).unwrap();
        assert!(runtime.matches(alias.as_raw_handle()));
        assert!(!runtime.matches(input.as_file().as_raw_handle()));
    }
}
