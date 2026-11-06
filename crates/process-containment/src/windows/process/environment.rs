#![cfg(windows)]
use super::error;
use std::io;
use std::{os::windows::ffi::OsStrExt as _, path::Path};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

/// Obtain only OS path metadata; never inherit credentials or arbitrary environment entries.
pub(super) fn block(local_data: &Path) -> io::Result<Vec<u16>> {
    let mut directory = vec![0u16; 32768];
    // SAFETY: the initialized output buffer has the declared capacity.
    let length = unsafe { GetWindowsDirectoryW(directory.as_mut_ptr(), 32768) } as usize;
    if length == 0 || length >= directory.len() {
        return Err(error("system-runtime-directory"));
    }
    let mut block = "LOCALAPPDATA=".encode_utf16().collect::<Vec<_>>();
    block.extend(local_data.as_os_str().encode_wide());
    block.push(0);
    block.extend("SystemRoot=".encode_utf16());
    block.extend_from_slice(&directory[..length]);
    block.extend_from_slice(&[0, 0]);
    Ok(block)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn child_environment_contains_only_required_os_paths() {
        let block = block(Path::new(r"C:\synthetic\Local")).unwrap();
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
