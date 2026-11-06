#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, allow(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::filesystem;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::enter;

mod launch;
pub use launch::{Child, Mode, Program};
mod verification;
pub use verification::verify_entry;

#[cfg(not(target_os = "linux"))]
pub fn enter(input: &std::fs::File) -> std::io::Result<()> {
    #[cfg(windows)]
    windows::process::verify_token(input)?;
    #[cfg(not(windows))]
    let _ = input;
    verify_entry()
}
