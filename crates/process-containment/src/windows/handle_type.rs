#![cfg(windows)]
//! Read an OS handle's counted type name without interpreting file handles as other objects.
use std::{io, ptr};
use windows_sys::{
    Wdk::Foundation::{NtQueryObject, ObjectTypeInformation},
    Win32::{Foundation::HANDLE, System::WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION},
};

/// None means the snapshot's handle was closed before inspection.
pub(super) fn file(handle: HANDLE) -> io::Result<Option<bool>> {
    let mut storage = [0usize; 128];
    let mut returned = 0;
    // SAFETY: the OS validates this snapshot handle. The aligned initialized
    // buffer is 1024 bytes on supported x64 Windows, bounded and retained here.
    let status = unsafe {
        NtQueryObject(
            handle,
            ObjectTypeInformation,
            storage.as_mut_ptr().cast(),
            u32::try_from(std::mem::size_of_val(&storage)).map_err(|_| denied())?,
            &raw mut returned,
        )
    };
    if status.cast_unsigned() == 0xc000_0008 {
        return Ok(None);
    }
    if status < 0
        || returned as usize > std::mem::size_of_val(&storage)
        || (returned as usize) < std::mem::size_of::<PUBLIC_OBJECT_TYPE_INFORMATION>()
    {
        return Err(denied());
    }
    // SAFETY: the successful bounded query initialized the public structure in
    // pointer-aligned storage with at least its exact size.
    let name =
        unsafe { ptr::read(storage.as_ptr().cast::<PUBLIC_OBJECT_TYPE_INFORMATION>()) }.TypeName;
    let start = storage.as_ptr() as usize;
    let address = name.Buffer as usize;
    let length = usize::from(name.Length);
    if length == 0
        || length > 128
        || !length.is_multiple_of(2)
        || name.Length > name.MaximumLength
        || !address.is_multiple_of(2)
        || address < start
        || address
            .checked_add(length)
            .is_none_or(|end| end > start + returned as usize)
    {
        return Err(denied());
    }
    if length != 8 {
        return Ok(Some(false));
    }
    // SAFETY: the checked pointer and eight-byte extent lie wholly inside the
    // initialized live local buffer. No raw pointer or borrowed slice escapes.
    Ok(Some(
        (unsafe { std::slice::from_raw_parts(name.Buffer, 4) }) == [70, 105, 108, 101],
    ))
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "EVTX handle type could not be verified",
    )
}
