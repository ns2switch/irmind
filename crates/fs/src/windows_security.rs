//! The only unsafe boundary in IRMind. All pointers and handles stay in this module.

use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation,
    IsValidSid, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

static ACL_UPDATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken returned this owned handle; it is closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalAllocation(HLOCAL);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: each value is allocated by a Win32 API documented to use LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn sid_size(subauthorities: u8) -> Option<usize> {
    (subauthorities <= 15).then(|| 8 + 4 * usize::from(subauthorities))
}

fn sid_fits_ace(ace_size: usize, sid_offset: usize, subauthorities: u8) -> bool {
    sid_size(subauthorities)
        .and_then(|size| sid_offset.checked_add(size))
        .is_some_and(|end| end <= ace_size)
}

fn current_user_sid() -> io::Result<Vec<u8>> {
    let mut raw_token = ptr::null_mut();
    // SAFETY: out pointer is valid; GetCurrentProcess returns a borrowed pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(raw_token);
    let mut required = 0u32;
    // SAFETY: null buffer is the documented size-query form.
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    if !(std::mem::size_of::<TOKEN_USER>() as u32..=4096).contains(&required) {
        return Err(denied("invalid user token size"));
    }
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let capacity = u32::try_from(words * std::mem::size_of::<usize>())
        .map_err(|_| denied("invalid user token size"))?;
    // SAFETY: buffer is aligned for TOKEN_USER and has capacity bytes; the token handle is live.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            capacity,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful GetTokenInformation initialized TOKEN_USER in the aligned buffer.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let start = buffer.as_ptr() as usize;
    let end = start + buffer.len() * std::mem::size_of::<usize>();
    let address = sid as usize;
    if address < start || address >= end {
        return Err(denied("user SID outside token buffer"));
    }
    if end - address < 8 {
        return Err(denied("user SID header exceeds token buffer"));
    }
    // SAFETY: the SID's eight-byte header lies inside the initialized token buffer.
    let subauthorities = unsafe { *sid.cast::<u8>().add(1) };
    let expected_length =
        sid_size(subauthorities).ok_or_else(|| denied("user SID has too many subauthorities"))?;
    if expected_length > end - address {
        return Err(denied("user SID exceeds token buffer"));
    }
    // SAFETY: the complete declared SID lies inside the initialized token buffer.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(denied("invalid user SID"));
    }
    // SAFETY: the SID was validated and its complete span remains in the live buffer.
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length != expected_length {
        return Err(denied("user SID length changed after validation"));
    }
    // SAFETY: the checked range is wholly inside the initialized token buffer.
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

fn sid_text(sid: &[u8]) -> io::Result<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: sid is a validated SID copied from the current process token; out pointer is valid.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation(raw.cast());
    let mut length = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a terminated UTF-16 allocation. Bound the scan.
    while length < 256 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(denied("user SID string too long"));
    }
    // SAFETY: the allocation remains live and length was bounded by its terminator.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| denied("invalid user SID string"))?;
    drop(allocation);
    Ok(text)
}

pub(crate) fn private_windows(path: &Path) -> io::Result<()> {
    // Win32 can expose an intermediate DACL while another thread updates the same path.
    let _acl_guard = ACL_UPDATE_LOCK
        .lock()
        .map_err(|_| denied("Windows ACL update lock is poisoned"))?;
    let metadata = fs::symlink_metadata(path)?;
    let sid = current_user_sid()?;
    let sid_text = sid_text(&sid)?;
    let flags = if metadata.is_dir() { "OICI" } else { "" };
    let sddl: Vec<u16> = format!("D:P(A;{flags};FA;;;{sid_text})")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: SDDL is terminated; out pointer is valid and freed below with LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _descriptor = LocalAllocation(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl: *mut ACL = ptr::null_mut();
    // SAFETY: descriptor is a live Win32 security descriptor; out pointers are valid.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0
        || acl.is_null()
    {
        return Err(denied("private descriptor has no DACL"));
    }
    let path_wide = wide_path(path);
    // SAFETY: path is terminated; acl remains live until the call returns.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    verify_private(path)
}

pub(crate) fn verify_private(path: &Path) -> io::Result<()> {
    let sid = current_user_sid()?;
    let metadata = fs::symlink_metadata(path)?;
    let path_wide = wide_path(path);
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: terminated path and valid out pointers; descriptor is freed with LocalFree.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalAllocation(descriptor);
    verify_acl(acl, descriptor, &sid, metadata.is_dir())
}

fn verify_acl(acl: *mut ACL, descriptor: *mut c_void, sid: &[u8], is_dir: bool) -> io::Result<()> {
    if descriptor.is_null() || acl.is_null() {
        return Err(denied("private file has no DACL"));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: descriptor is live; control and revision are valid out pointers.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(denied("Windows DACL is not protected"));
    }
    // SAFETY: acl is a live pointer obtained from the security descriptor.
    if unsafe { (*acl).AceCount } != 1 {
        return Err(denied("Windows DACL has unexpected ACEs"));
    }
    let mut raw_ace: *mut c_void = ptr::null_mut();
    // SAFETY: acl is live and index zero exists because AceCount is one.
    if unsafe { GetAce(acl, 0, &mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(denied("Windows DACL has no user ACE"));
    }
    let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
    // SAFETY: GetAce returned a live ACE; check the header size before reading later fields.
    let header = unsafe { (*ace).Header };
    if header.AceType != 0
        || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(denied("Windows DACL ACE has an invalid type or size"));
    }
    let expected_flags = if is_dir {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        0
    };
    // SAFETY: the ACE header established enough bytes for Mask and SidStart.
    let mask = unsafe { (*ace).Mask };
    if header.AceFlags != expected_flags || mask != FILE_ALL_ACCESS {
        return Err(denied("Windows DACL grants unexpected rights"));
    }
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if usize::from(header.AceSize) < sid_offset + 8 {
        return Err(denied("Windows DACL ACE has a truncated SID"));
    }
    // SAFETY: the ACE has at least the eight-byte SID header, checked above.
    let ace_sid: *mut c_void = unsafe { ptr::addr_of!((*ace).SidStart).cast_mut().cast() };
    // SAFETY: the subauthority count is the second byte of that checked SID header.
    let subauthorities = unsafe { *ace_sid.cast::<u8>().add(1) };
    if !sid_fits_ace(usize::from(header.AceSize), sid_offset, subauthorities) {
        return Err(denied("Windows DACL ACE SID exceeds its bounds"));
    }
    // SAFETY: the SID span is within the ACE; Windows validates the SID structure.
    if unsafe { IsValidSid(ace_sid) } == 0 {
        return Err(denied("Windows DACL ACE has an invalid SID"));
    }
    // SAFETY: both SIDs are validated and live for the duration of the call.
    if unsafe { EqualSid(ace_sid, sid.as_ptr().cast_mut().cast()) } == 0 {
        return Err(denied("Windows DACL belongs to another user"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{sid_fits_ace, sid_size};

    #[test]
    fn ace_sid_length_is_bounded_before_win32_reads_it() {
        assert!(sid_fits_ace(20, 8, 1));
        assert!(!sid_fits_ace(19, 8, 1));
        assert!(!sid_fits_ace(200, 8, 16));
    }

    #[test]
    fn token_sid_length_is_bounded_before_win32_reads_it() {
        assert_eq!(sid_size(0), Some(8));
        assert_eq!(sid_size(15), Some(68));
        assert_eq!(sid_size(16), None);
        assert!(sid_size(15).is_some_and(|size| size <= 68));
        assert!(!sid_size(15).is_some_and(|size| size <= 67));
    }
}

pub(crate) fn durable_rename(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "seal already exists",
        ));
    }
    let source = wide_path(source);
    let destination = wide_path(destination);
    // SAFETY: both paths are terminated and live; no REPLACE_EXISTING flag is supplied.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn durable_replace(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide_path(source);
    let destination = wide_path(destination);
    // SAFETY: both paths are terminated and live; replacement is confined to the caller's private directory.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING
                | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
