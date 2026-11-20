#![cfg(windows)]
pub mod filesystem;

mod handle_snapshot;
mod handle_type;
mod handles;
pub(crate) mod network;
#[cfg(feature = "launcher")]
pub(crate) mod process;
mod runtime_directory;
pub(crate) mod token;

pub(super) fn error(stage: &'static str) -> std::io::Error {
    // SAFETY: GetLastError takes no pointers and reads this thread's last-error value.
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    let message = format!("Windows EVTX containment failed at {stage} (error {code})");
    #[cfg(all(feature = "launcher", debug_assertions))]
    startup_diagnostic(format_args!("{message}"));
    std::io::Error::other(message)
}

#[cfg(all(feature = "launcher", debug_assertions))]
pub(crate) fn startup_diagnostic(message: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{message}");
}
