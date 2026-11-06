#![cfg(windows)]
use super::error;
use std::{io, os::windows::ffi::OsStringExt as _, path::PathBuf, ptr};
use windows_sys::Win32::{
    Security::{
        Authorization::ConvertSidToStringSidW,
        Isolation::{
            CreateAppContainerProfile, DeleteAppContainerProfile, GetAppContainerFolderPath,
        },
        PSID,
    },
    System::Com::CoTaskMemFree,
};

/// A unique, empty OS namespace. The child receives no write access to its profile.
pub(super) struct Profile {
    name: Vec<u16>,
    local_data: PathBuf,
}
impl Profile {
    pub(super) fn create(name: Vec<u16>) -> io::Result<(Self, PSID)> {
        let mut sid = ptr::null_mut();
        // SAFETY: all three names are terminated and live; zero capabilities; valid SID output pointer.
        let status = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                ptr::null(),
                0,
                &raw mut sid,
            )
        };
        if status < 0 || sid.is_null() {
            return Err(io::Error::other(format!(
                "Windows EVTX profile creation failed ({status:#x})"
            )));
        }
        let mut profile = Self {
            name,
            local_data: PathBuf::new(),
        };
        let restricted = restrict_profile(sid);
        if let Err(failure) = restricted {
            // SAFETY: successful CreateAppContainerProfile allocated this SID; ownership was not returned.
            unsafe { windows_sys::Win32::Security::FreeSid(sid) };
            return Err(failure);
        }
        profile.local_data = restricted?;
        Ok((profile, sid))
    }
    pub(super) fn local_data(&self) -> &std::path::Path {
        &self.local_data
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        // SAFETY: this unique profile was created by this object and cannot have a live child when dropped.
        unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
    }
}

fn profile_directory(sid: PSID) -> io::Result<PathBuf> {
    let mut text = ptr::null_mut();
    // SAFETY: sid is the live SID returned by CreateAppContainerProfile; output is initialized by this API.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(error("profile-SID"));
    }
    let mut path = ptr::null_mut();
    // SAFETY: text is a terminated SID string; valid output pointer.
    let status = unsafe { GetAppContainerFolderPath(text, &raw mut path) };
    // SAFETY: ConvertSidToStringSidW allocated text using LocalAlloc; no subsequent reference remains.
    unsafe { windows_sys::Win32::Foundation::LocalFree(text.cast()) };
    if status < 0 || path.is_null() {
        return Err(io::Error::other(
            "Windows EVTX profile directory is unavailable",
        ));
    }
    let mut length = 0;
    // SAFETY: successful GetAppContainerFolderPath returns a terminated allocated UTF-16 path.
    while unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the allocation contains length initialized UTF-16 units as scanned above.
    let directory = PathBuf::from(std::ffi::OsString::from_wide(unsafe {
        std::slice::from_raw_parts(path, length)
    }));
    // SAFETY: GetAppContainerFolderPath documents CoTaskMemFree for this allocation.
    unsafe { CoTaskMemFree(path.cast()) };
    Ok(directory)
}

fn restrict_profile(sid: PSID) -> io::Result<PathBuf> {
    // SAFETY: successful CreateAppContainerProfile returned this live, complete SID.
    let length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
    if !(8..=256).contains(&length) {
        return Err(error("profile-SID-length"));
    }
    // SAFETY: GetLengthSid validated the byte extent of the retained SID allocation.
    let sid_bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) };
    let directory = profile_directory(sid)?;
    let root = directory.parent().ok_or_else(|| error("profile-parent"))?;
    let packages = root
        .parent()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("Packages"))
        })
        .ok_or_else(|| io::Error::other("Windows EVTX profile location is unsupported"))?;
    let local_data = packages
        .parent()
        .ok_or_else(|| error("profile-local-data"))?
        .to_path_buf();
    // Remove package-write grants from every OS-created entry before the child exists.
    let mut pending = vec![(root.to_path_buf(), 0u8)];
    let mut count = 0;
    while let Some((path, depth)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path)?;
        count += 1;
        if depth > 8 || count > 1024 || metadata.file_type().is_symlink() {
            return Err(io::Error::other(
                "Windows EVTX profile has unexpected entries",
            ));
        }
        super::super::super::filesystem::helper_read_execute(&path, sid_bytes)?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                pending.push((entry?.path(), depth + 1));
            }
        }
    }
    Ok(local_data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn profile_is_removed_after_startup_scope_ends() {
        let root = tempfile::tempdir().unwrap();
        let name = format!(
            "irmind-test-{}",
            root.path().file_name().unwrap().to_string_lossy()
        );
        let (profile, sid) = Profile::create(name.encode_utf16().chain(Some(0)).collect()).unwrap();
        let directory = profile_directory(sid).unwrap();
        assert!(directory.is_dir());
        // SAFETY: successful Profile::create returned this owned SID; no SID references remain.
        unsafe { windows_sys::Win32::Security::FreeSid(sid) };
        drop(profile);
        assert!(!directory.exists(), "profile namespace was not cleaned up");
    }
}
