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

#[cfg(feature = "launcher")]
mod launch;
#[cfg(feature = "launcher")]
pub use launch::{Child, Mode, Program, WitnessStats};
mod verification;
#[cfg(any(windows, test, feature = "fuzzing"))]
mod witness_protocol;
pub use verification::verify_entry;

#[cfg(not(target_os = "linux"))]
pub fn enter(input: &std::fs::File) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        windows::network::enter(input)
    }
    #[cfg(not(windows))]
    {
        let _ = input;
        verify_entry()
    }
}

#[cfg(windows)]
pub fn network_witness(input: &std::fs::File) -> std::io::Result<()> {
    windows::network::witness(input)
}
