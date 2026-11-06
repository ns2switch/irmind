#![cfg(windows)]
pub mod filesystem;

mod handles;
#[cfg(feature = "launcher")]
pub(crate) mod process;
mod runtime_directory;
pub(crate) mod token;

pub(super) fn error(stage: &'static str) -> std::io::Error {
    // SAFETY: GetLastError takes no pointers and reads this thread's last-error value.
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    std::io::Error::other(format!(
        "Windows EVTX containment failed at {stage} (error {code})"
    ))
}
