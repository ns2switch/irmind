use std::{
    fs, io,
    net::{Ipv4Addr, Ipv6Addr, TcpListener},
};

pub(crate) const CANARY: &str = "irmind-containment-canary";

fn blocked<T>(result: io::Result<T>) -> bool {
    result.is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
}

/// Invoked after native enforcement and before any decoder input is processed.
pub fn verify_entry() -> io::Result<()> {
    let file = blocked(fs::read(CANARY));
    let ipv4 = blocked(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    let ipv6 = blocked(TcpListener::bind((Ipv6Addr::LOCALHOST, 0)));
    #[cfg(target_os = "linux")]
    {
        let netlink = rustix::net::socket_with(
            rustix::net::AddressFamily::NETLINK,
            rustix::net::SocketType::RAW,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(io::Error::from);
        if !blocked(netlink) || !blocked(std::os::unix::net::UnixStream::pair()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "EVTX network-family isolation failed",
            ));
        }
    }
    if !file || !ipv4 || !ipv6 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "EVTX isolation verification failed: foreign reads or network access were not denied",
        ));
    }
    Ok(())
}
