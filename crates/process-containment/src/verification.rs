use std::{
    fs, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

pub(crate) const CANARY: &str = "irmind-containment-canary";

fn blocked<T>(result: io::Result<T>) -> bool {
    result.is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
}

/// Invoked after native enforcement and before any decoder input is processed.
pub fn verify_entry() -> io::Result<()> {
    verify_files()?;
    let ipv4 = blocked(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    let ipv6 = blocked(TcpListener::bind((Ipv6Addr::LOCALHOST, 0)));
    // Only loopback is probed; failure must be policy denial, never refusal/timeout.
    let connections = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 9)),
    ]
    .map(|address| TcpStream::connect_timeout(&address, Duration::from_millis(100)));
    let outbound = connections.iter().all(|result| {
        result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
    });
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
    if !ipv4 || !ipv6 || !outbound {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "EVTX isolation verification failed: ipv4_bind_denied={ipv4}, ipv6_bind_denied={ipv6}, outbound_denied={outbound}, outbound_ipv4={}, outbound_ipv6={}",
                connection_outcome(&connections[0]),
                connection_outcome(&connections[1])
            ),
        ));
    }
    Ok(())
}

fn connection_outcome(result: &io::Result<TcpStream>) -> String {
    match result {
        Ok(_) => "connected".into(),
        Err(error) => format!("{:?}/{}", error.kind(), error.raw_os_error().unwrap_or(0)),
    }
}

pub(crate) fn verify_files() -> io::Result<()> {
    let file = blocked(fs::read(CANARY));
    let write = blocked(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open("irmind-write-canary"),
    );
    if !file || !write {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "EVTX file isolation verification failed",
        ));
    }
    Ok(())
}
