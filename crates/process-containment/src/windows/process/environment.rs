#![cfg(windows)]
use super::error;
use std::{io, ptr};
use windows_sys::Win32::{
    System::{Com::CoTaskMemFree, SystemInformation::GetWindowsDirectoryW},
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

/// Obtain only OS path metadata; never inherit credentials or arbitrary environment entries.
pub(super) fn block() -> io::Result<Vec<u16>> {
    let mut directory = vec![0u16; 32768];
    // SAFETY: the initialized output buffer has the declared capacity.
    let length = unsafe { GetWindowsDirectoryW(directory.as_mut_ptr(), 32768) } as usize;
    if length == 0 || length >= directory.len() {
        return Err(error("system-runtime-directory"));
    }
    let mut block = "LOCALAPPDATA=".encode_utf16().collect::<Vec<_>>();
    block.extend(local_data()?);
    block.push(0);
    block.extend("SystemRoot=".encode_utf16());
    block.extend_from_slice(&directory[..length]);
    block.extend_from_slice(&[0, 0]);
    Ok(block)
}

fn local_data() -> io::Result<Vec<u16>> {
    let mut path = ptr::null_mut();
    let folder = FOLDERID_LocalAppData;
    // SAFETY: known folder GUID, default current-user token, initialized output pointer.
    let status =
        unsafe { SHGetKnownFolderPath(&raw const folder, 0, ptr::null_mut(), &raw mut path) };
    if status < 0 || path.is_null() {
        return Err(io::Error::other(
            "Windows EVTX LocalAppData directory is unavailable",
        ));
    }
    let mut length = 0;
    // SAFETY: successful SHGetKnownFolderPath returns a terminated allocated UTF-16 string.
    while unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: length initialized units precede the terminator in the allocation.
    let directory = unsafe { std::slice::from_raw_parts(path, length) }.to_vec();
    // SAFETY: SHGetKnownFolderPath documents CoTaskMemFree for the returned allocation.
    unsafe { CoTaskMemFree(path.cast()) };
    Ok(directory)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn child_environment_contains_only_required_os_paths() {
        let block = block().unwrap();
        assert!(block.ends_with(&[0, 0]));
        let entries = block
            .split(|unit| *unit == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf16(entry).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].starts_with("LOCALAPPDATA="));
        assert!(entries[1].starts_with("SystemRoot="));
    }
}
