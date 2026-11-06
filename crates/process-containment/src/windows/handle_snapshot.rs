#![cfg(windows)]
//! Inspect a bounded OS handle snapshot, never guessed numeric handle values.
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_ITEMS, HANDLE},
    System::{
        Diagnostics::ProcessSnapshotting::{
            HPSS, HPSSWALK, PSS_CAPTURE_HANDLES, PSS_HANDLE_ENTRY, PSS_WALK_HANDLES,
            PssCaptureSnapshot, PssFreeSnapshot, PssWalkMarkerCreate, PssWalkMarkerFree,
            PssWalkSnapshot,
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

pub(super) fn inspect(mut check: impl FnMut(HANDLE, bool) -> io::Result<()>) -> io::Result<()> {
    let snapshot = capture()?;
    let mut raw = ptr::null_mut();
    // SAFETY: null requests the default allocator; raw is valid output storage.
    let status = unsafe { PssWalkMarkerCreate(ptr::null(), &raw mut raw) };
    if status != 0 {
        return Err(denied("marker", status));
    }
    let marker = Marker(raw);
    let size =
        u32::try_from(std::mem::size_of::<PSS_HANDLE_ENTRY>()).map_err(|_| denied("size", 0))?;
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
        if status != 0 {
            return Err(denied("walk", status));
        }
        if let Some(file) = super::handle_type::file(entry.Handle)? {
            check(entry.Handle, file)?;
        }
    }
    Err(denied("walk-limit", MAX_HANDLES))
}
fn capture() -> io::Result<Snapshot> {
    let mut count = 0;
    // SAFETY: borrowed current-process pseudo-handle and valid output storage.
    if unsafe { GetProcessHandleCount(GetCurrentProcess(), &raw mut count) } == 0
        || count > MAX_HANDLES
    {
        return Err(denied("count", count));
    }
    let mut raw = ptr::null_mut();
    let flags = PSS_CAPTURE_HANDLES;
    // SAFETY: capture only this process's bounded handle metadata, never a VA
    // clone, child process or breakaway; raw is valid output storage.
    let status = unsafe { PssCaptureSnapshot(GetCurrentProcess(), flags, 0, &raw mut raw) };
    if status != 0 {
        return Err(denied("capture", status));
    }
    Ok(Snapshot(raw))
}
fn denied(stage: &'static str, status: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("EVTX Windows handle snapshot could not be verified ({stage}, {status:#x})"),
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
        inspect(|handle, kind_file| {
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
