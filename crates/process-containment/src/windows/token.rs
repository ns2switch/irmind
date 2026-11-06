#![cfg(windows)]
use super::{error, handles::Handle};
use std::{io, ptr};
use windows_sys::Win32::{
    Security::{
        GetTokenInformation, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenCapabilities,
        TokenIsAppContainer,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
pub(crate) fn verify_token(input: &std::fs::File) -> io::Result<()> {
    let mut raw = ptr::null_mut();
    // SAFETY: current process is a borrowed pseudo-handle; output transfers one owned token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(error("token-open"));
    }
    let token = Handle::new(raw)?;
    if query(&token, TokenIsAppContainer)? != 1 || query(&token, TokenCapabilities)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "EVTX requires an AppContainer token without network capabilities",
        ));
    }
    verify_inherited_files(input)
}

fn verify_inherited_files(input: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT},
        Storage::FileSystem::{FILE_TYPE_DISK, GetFileType},
        System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
    };
    // SAFETY: queries the borrowed standard input handle; it is never closed here.
    let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    // SAFETY: both are borrowed standard handles, queried without transferring ownership.
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    // SAFETY: the standard error query has no input pointers and returns a borrowed handle.
    let errors = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    let evidence = input.as_raw_handle();
    let runtime = super::runtime_directory::RuntimeDirectory::open()?;
    // Windows handle values are multiples of four. Check a bounded low range
    // including the inheritable-canary handles used by the native launch tests.
    for value in (4usize..65_536).step_by(4) {
        let handle = value as *mut std::ffi::c_void;
        if [stdin, output, errors, evidence].contains(&handle) {
            continue;
        }
        let mut flags = 0;
        // SAFETY: query APIs validate arbitrary handle values; no pointer is dereferenced.
        if unsafe { GetHandleInformation(handle, &raw mut flags) } != 0 {
            // SAFETY: successful handle query established a live handle in this process.
            let disk = unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
            if flags & HANDLE_FLAG_INHERIT != 0 || (disk && !runtime.matches(handle)) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "EVTX inherited an unrelated file handle",
                ));
            }
        }
    }
    Ok(())
}
fn query(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> io::Result<u32> {
    let mut size = 0;
    // SAFETY: null buffer is the documented size query; output pointer and token are valid.
    unsafe { GetTokenInformation(token.raw(), class, ptr::null_mut(), 0, &raw mut size) };
    if !(4..=4096).contains(&size) {
        return Err(error("token-size"));
    }
    let size_usize = usize::try_from(size).map_err(|_| error("token-size"))?;
    let mut words = vec![0usize; size_usize.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: allocation is pointer-aligned and covers the entire requested result, including TOKEN_GROUPS pointers.
    if unsafe {
        GetTokenInformation(
            token.raw(),
            class,
            words.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    } == 0
    {
        return Err(error("token-query"));
    }
    let mask = usize::try_from(u32::MAX).map_err(|_| error("token-mask"))?;
    u32::try_from(words[0] & mask).map_err(|_| error("token-value"))
}
