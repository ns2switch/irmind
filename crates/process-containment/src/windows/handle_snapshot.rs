#![cfg(windows)]
//! Inspect a bounded OS handle snapshot, never guessed numeric handle values.
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_ITEMS, HANDLE},
    System::{
        Diagnostics::ProcessSnapshotting::{
            HPSS, HPSSWALK, PSS_CAPTURE_HANDLE_BASIC_INFORMATION,
            PSS_CAPTURE_HANDLE_NAME_INFORMATION, PSS_CAPTURE_HANDLES, PSS_HANDLE_ENTRY,
            PSS_HANDLE_HAVE_TYPE, PSS_WALK_HANDLES, PssCaptureSnapshot, PssFreeSnapshot,
            PssWalkMarkerCreate, PssWalkMarkerFree, PssWalkSnapshot,
        },
        Threading::{GetCurrentProcess, GetProcessHandleCount},
    },
};
const MAX_HANDLES: u32 = 512;
struct Snapshot(HPSS);
impl Drop for Snapshot {
    fn drop(&mut self) {
        // SAFETY: this object owns the live snapshot of its own process, freed once.
        unsafe { PssFreeSnapshot(GetCurrentProcess(), self.0) };
    }
}
struct Marker(HPSSWALK);
impl Drop for Marker {
    fn drop(&mut self) {
        // SAFETY: this object owns a successfully created marker, freed once.
        unsafe { PssWalkMarkerFree(self.0) };
    }
}

pub(super) fn inspect(
    mut check: impl FnMut(HANDLE, bool, u32) -> io::Result<()>,
) -> io::Result<()> {
    let snapshot = capture()?;
    let mut raw = ptr::null_mut();
    // SAFETY: null requests the default allocator; raw is valid output storage.
    if unsafe { PssWalkMarkerCreate(ptr::null(), &raw mut raw) } != 0 {
        return Err(denied());
    }
    let marker = Marker(raw);
    let size = u32::try_from(std::mem::size_of::<PSS_HANDLE_ENTRY>()).map_err(|_| denied())?;
    for _ in 0..=MAX_HANDLES {
        let mut entry = PSS_HANDLE_ENTRY::default();
        // SAFETY: snapshot and marker are live; aligned output and exact size match
        // PSS_WALK_HANDLES. Returned pointers remain live until the next walk.
        let status = unsafe {
            PssWalkSnapshot(
                snapshot.0,
                PSS_WALK_HANDLES,
                marker.0,
                (&raw mut entry).cast(),
                size,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(());
        }
        if status != 0 || entry.Flags & PSS_HANDLE_HAVE_TYPE == 0 {
            return Err(denied());
        }
        let file = if entry.TypeNameLength == 8 && !entry.TypeName.is_null() {
            // SAFETY: the OS entry declares eight live bytes; the marker remains
            // retained and no further walk occurs until this borrowed slice ends.
            (unsafe { std::slice::from_raw_parts(entry.TypeName, 4) }) == [70, 105, 108, 101]
        } else {
            false
        };
        check(entry.Handle, file, entry.GrantedAccess)?;
    }
    Err(denied())
}
fn capture() -> io::Result<Snapshot> {
    let mut count = 0;
    // SAFETY: borrowed current-process pseudo-handle and valid output storage.
    if unsafe { GetProcessHandleCount(GetCurrentProcess(), &raw mut count) } == 0
        || count > MAX_HANDLES
    {
        return Err(denied());
    }
    let mut raw = ptr::null_mut();
    let flags = PSS_CAPTURE_HANDLES
        | PSS_CAPTURE_HANDLE_NAME_INFORMATION
        | PSS_CAPTURE_HANDLE_BASIC_INFORMATION;
    // SAFETY: capture only this process's bounded handle metadata, never a VA
    // clone, child process or breakaway; raw is valid output storage.
    if unsafe { PssCaptureSnapshot(GetCurrentProcess(), flags, 0, &raw mut raw) } != 0 {
        return Err(denied());
    }
    Ok(Snapshot(raw))
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "EVTX Windows handle snapshot could not be verified",
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::windows::io::AsRawHandle as _;

    #[test]
    fn snapshot_includes_a_real_file_without_guessing_handle_values() {
        let file = tempfile::tempfile().unwrap();
        let mut found = false;
        inspect(|handle, kind_file, _access| {
            if handle == file.as_raw_handle() {
                assert!(kind_file);
                found = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(found);
    }
}
