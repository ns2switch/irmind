#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::Program;
use std::os::windows::io::AsRawHandle as _;

fn program(root: &std::path::Path) -> Program {
    let path = std::env::var_os("IRMIND_EVTX_HELPER_TEST")
        .expect("native CI must supply its compiled helper");
    Program::new(std::path::Path::new(&path), root).unwrap()
}
#[test]
fn unrelated_inheritable_file_is_excluded_and_job_terminates_child() {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    let root = tempfile::tempdir().unwrap();
    let foreign = root.path().join("unrelated-private-canary");
    std::fs::write(&foreign, b"not evidence").unwrap();
    let file = File::open(foreign).unwrap();
    // SAFETY: live file; only its inheritability flag changes for this test.
    assert_ne!(
        // SAFETY: the live file owns the handle and only the documented inheritability flag changes.
        unsafe {
            SetHandleInformation(
                file.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        },
        0
    );
    let program = program(root.path());
    let mut child = program.probe().unwrap();
    let mut out = String::new();
    child
        .take_stdout()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(child.try_wait().unwrap(), Some(true), "{out}");
    assert!(out.contains("\"isolated\":true"));
    child.terminate().unwrap();
    drop(child);
    drop(program);
    drop(file);
    std::fs::remove_file(root.path().join("unrelated-private-canary")).unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
#[test]
fn invalid_executable_cleans_up_private_child_runtime() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("not-an-executable.exe");
    std::fs::write(&executable, b"synthetic invalid executable").unwrap();
    let program = Program::new(&executable, root.path()).unwrap();
    for _ in 0..3 {
        assert!(program.probe().is_err());
    }
    drop(program);
    std::fs::remove_file(executable).unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
