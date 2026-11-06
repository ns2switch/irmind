#![cfg(windows)]
use crate::witness_protocol::denied;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};
#[cfg(feature = "launcher")]
use std::{thread, time::Instant};
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
pub(super) struct Listeners([TcpListener; 2]);
pub(super) fn address(index: usize, port: u16) -> SocketAddr {
    if index == 0 {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    } else {
        SocketAddr::from((Ipv6Addr::LOCALHOST, port))
    }
}
impl Listeners {
    pub(super) fn bind() -> io::Result<Self> {
        let listeners = [
            TcpListener::bind(address(0, 0))?,
            TcpListener::bind(address(1, 0))?,
        ];
        for listener in &listeners {
            listener.set_nonblocking(true)?;
        }
        Ok(Self(listeners))
    }
    pub(super) fn ports(&self) -> io::Result<[u16; 2]> {
        Ok([
            self.0[0].local_addr()?.port(),
            self.0[1].local_addr()?.port(),
        ])
    }
    pub(super) fn empty(&self) -> io::Result<()> {
        for listener in &self.0 {
            match listener.accept() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                _ => return Err(denied()),
            }
        }
        Ok(())
    }
    #[cfg(feature = "launcher")]
    pub(super) fn positive_control(&self) -> io::Result<()> {
        self.empty()?;
        for (index, port) in self.ports()?.into_iter().enumerate() {
            let _connected = TcpStream::connect_timeout(&address(index, port), CONNECT_TIMEOUT)?;
            let start = Instant::now();
            loop {
                match self.0[index].accept() {
                    Ok(_) => break,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && start.elapsed() < CONNECT_TIMEOUT =>
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    _ => return Err(denied()),
                }
            }
        }
        self.empty()
    }
}
/// Only a candidate: callers must also verify live endpoints and no accepted flow.
pub(super) fn blocked_candidates(ports: [u16; 2]) -> io::Result<()> {
    for (index, port) in ports.into_iter().enumerate() {
        match TcpStream::connect_timeout(&address(index, port), CONNECT_TIMEOUT) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::TimedOut
                ) => {}
            _ => return Err(denied()),
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "launcher"))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn positive_controls_and_an_unconfined_connection_cannot_pass_a_denial_witness() {
        let listeners = Listeners::bind().unwrap();
        listeners.positive_control().unwrap();
        assert!(blocked_candidates(listeners.ports().unwrap()).is_err());
        assert!(listeners.empty().is_err());
    }
}
