#![cfg(windows)]
use super::{error, handles::Handle};
use std::{io, ptr};
use windows_sys::Win32::{
    Security::{
        GetTokenInformation, TOKEN_APPCONTAINER_INFORMATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
        TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
pub(crate) fn verify_token(input: &std::fs::File, expected: &[u8]) -> io::Result<()> {
    // SAFETY: borrowed current-process pseudo-handle; no ownership is transferred.
    verify_created(unsafe { GetCurrentProcess() }, expected)?;
    verify_inherited_files(input)
}
pub(crate) fn verify_created(
    process: windows_sys::Win32::Foundation::HANDLE,
    expected: &[u8],
) -> io::Result<()> {
    let mut raw = ptr::null_mut();
    // SAFETY: borrowed live process handle and valid output; transfers one owned token.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(error("token-open"));
    }
    let token = Handle::new(raw)?;
    if query(&token, TokenIsAppContainer)? != 1
        || query(&token, TokenCapabilities)? != 0
        || !profile_matches(&token, expected)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "EVTX requires the verified AppContainer profile without network capabilities",
        ));
    }
    Ok(())
}
fn profile_matches(token: &Handle, expected: &[u8]) -> io::Result<bool> {
    let mut words = vec![0usize; 64];
    let mut returned = 0;
    let capacity = u32::try_from(std::mem::size_of_val(words.as_slice()))
        .map_err(|_| error("profile-size"))?;
    // SAFETY: live token; aligned initialized output is large enough for the
    // public pointer structure and the bounded SID; returned length is checked.
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TokenAppContainerSid,
            words.as_mut_ptr().cast(),
            capacity,
            &raw mut returned,
        )
    } == 0
        || returned > capacity
        || (returned as usize) < std::mem::size_of::<TOKEN_APPCONTAINER_INFORMATION>()
    {
        return Err(error("profile-query"));
    }
    // SAFETY: a successful query initialized the public structure in the checked aligned buffer.
    let sid =
        unsafe { (*words.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer };
    let start = words.as_ptr() as usize;
    let address = sid as usize;
    if expected.len() < 8
        || expected.len() > 68
        || address < start
        || address
            .checked_add(expected.len())
            .is_none_or(|end| end > start + returned as usize)
    {
        return Err(error("profile-SID-bound"));
    }
    // SAFETY: exact expected SID extent lies inside the live initialized query buffer.
    Ok((unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), expected.len()) }) == expected)
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
    let runtime = super::runtime_directory::RuntimeDirectory::open(input)?;
    super::handle_snapshot::inspect(|handle, file| {
        if [stdin, output, errors, evidence].contains(&handle) {
            return Ok(());
        }
        let mut flags = 0;
        // SAFETY: the snapshot supplies a real handle from this process; output
        // points to initialized storage. A closed handle fails verification.
        if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
            return Err(error("snapshot-handle-query"));
        }
        // SAFETY: snapshot type information identifies File objects; never call
        // GetFileType on arbitrary process, synchronization or guessed handles.
        let disk = file && unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
        let expected_runtime = disk && runtime.matches(handle);
        if flags & HANDLE_FLAG_INHERIT != 0 || (disk && !expected_runtime) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "EVTX inherited an unrelated file handle (flags={flags:#x}, {})",
                    runtime.diagnostic(handle)
                ),
            ));
        }
        Ok(())
    })
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
