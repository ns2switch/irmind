//! Platform authentication for an IRMind-owned approval presentation.
//! The application owns expiry, binding, custody and signing.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(windows)]
mod windows_hello;
#[cfg(windows)]
pub use windows_hello::verify;

#[cfg(target_os = "macos")]
mod touch_id;
#[cfg(target_os = "macos")]
pub use touch_id::verify_touch_id;
