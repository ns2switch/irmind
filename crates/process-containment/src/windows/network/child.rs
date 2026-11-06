#![cfg(windows)]
use super::{
    files,
    sockets::{Listeners, blocked_candidates},
};
use crate::witness_protocol::{self as protocol, Ticket, denied};
use std::{
    fs::File,
    io::{self, Write as _},
    path::Path,
    thread,
    time::{Duration, Instant},
};
fn ticket(input: &File, witness: bool) -> io::Result<Ticket> {
    let ticket = Ticket::parse(&files::read(Path::new(protocol::TICKET))?)?;
    if ticket.witness != witness {
        return Err(denied());
    }
    super::super::token::verify_token(input, &ticket.sid)?;
    crate::verification::verify_files()?;
    Ok(ticket)
}
pub(crate) fn enter(input: &File) -> io::Result<()> {
    ticket(input, false).map(|_| ())
}
pub(crate) fn witness(input: &File) -> io::Result<()> {
    let ticket = ticket(input, true)?;
    let listeners = Listeners::bind()?;
    blocked_candidates(ticket.ports)?;
    print!("{}", protocol::ready(&ticket.nonce, listeners.ports()?));
    io::stdout().flush()?;
    wait_ack(
        &listeners,
        &ticket.nonce,
        Path::new(protocol::ACK),
        Duration::from_secs(5),
    )?;
    listeners.empty()?;
    print!("{}", protocol::receipt(&ticket.nonce, true));
    io::stdout().flush()
}

fn wait_ack(
    listeners: &Listeners,
    nonce: &[u8; 32],
    path: &Path,
    timeout: Duration,
) -> io::Result<()> {
    let start = Instant::now();
    loop {
        listeners.empty()?;
        match files::read(path) {
            Ok(bytes) => {
                protocol::check_receipt(&bytes, nonce, false)?;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && start.elapsed() < timeout => {}
            _ => return Err(denied()),
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn missing_or_wrong_nonce_acknowledgements_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ack");
        let listeners = Listeners::bind().unwrap();
        assert!(wait_ack(&listeners, &[1; 32], &path, Duration::from_millis(20)).is_err());
        std::fs::write(&path, protocol::receipt(&[2; 32], false)).unwrap();
        assert!(wait_ack(&listeners, &[1; 32], &path, Duration::from_millis(20)).is_err());
        std::fs::write(&path, protocol::receipt(&[1; 32], false)).unwrap();
        wait_ack(&listeners, &[1; 32], &path, Duration::from_millis(20)).unwrap();
    }
}
