#![cfg(windows)]
mod child;
#[cfg(feature = "launcher")]
mod exchange;
mod files;
#[cfg(feature = "launcher")]
mod services;
#[cfg(feature = "launcher")]
mod session;
mod sockets;
pub(crate) use child::{enter, witness};
#[cfg(feature = "launcher")]
pub(crate) use session::{Lease, ServiceStamp, Session};

#[cfg(feature = "launcher")]
pub(crate) fn write_ticket(
    path: &std::path::Path,
    bytes: &[u8],
    identity: &super::process::Identity,
) -> std::io::Result<()> {
    files::write(path, bytes, identity)
}
#[cfg(feature = "launcher")]
pub(crate) fn nonce() -> std::io::Result<[u8; 32]> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut nonce = [0u8; 32];
    // SAFETY: the system RNG initializes the exact live output buffer; null selects the system provider.
    if unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            nonce.as_mut_ptr(),
            32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return Err(crate::witness_protocol::denied());
    }
    Ok(nonce)
}
