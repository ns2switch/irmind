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
pub use verification::{process_creation_denied, verify_entry};

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

/// Exercise the bounded witness message codec without invoking the platform sandbox.
#[cfg(feature = "fuzzing")]
pub fn fuzz_witness_protocol(bytes: &[u8]) {
    use witness_protocol::{Ticket, check_receipt, parse_ready};
    if let Ok(ticket) = Ticket::parse(bytes) {
        let _ = Ticket::parse(ticket.encode().as_bytes());
        let _ = parse_ready(
            witness_protocol::ready(&ticket.nonce, ticket.ports).as_bytes(),
            &ticket.nonce,
        );
    }
    let _ = parse_ready(bytes, &[0; 32]);
    let _ = check_receipt(bytes, &[0; 32], false);
    let _ = check_receipt(bytes, &[0; 32], true);
}
