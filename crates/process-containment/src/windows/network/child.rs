#![cfg(windows)]
use super::{
    diagnostics as diag, files,
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
    let ticket = ticket(input, true).map_err(|_| diag::child_failure(diag::CHILD_TICKET))?;
    let listeners = Listeners::bind().map_err(|_| diag::child_failure(diag::CHILD_BIND))?;
    blocked_candidates(ticket.ports).map_err(|_| diag::child_failure(diag::CHILD_OUTBOUND))?;
    print!("{}", protocol::ready(&ticket.nonce, listeners.ports()?));
    io::stdout()
        .flush()
        .map_err(|_| diag::child_failure(diag::CHILD_READY_WRITE))?;
    wait_ack(
        &listeners,
        &ticket.nonce,
        Path::new(protocol::ACK),
        Duration::from_secs(5),
    )?;
    listeners
        .empty()
        .map_err(|_| diag::child_failure(diag::CHILD_FINAL_LISTENER))?;
    print!("{}", protocol::receipt(&ticket.nonce, true));
    io::stdout()
        .flush()
        .map_err(|_| diag::child_failure(diag::CHILD_COMPLETE_WRITE))
}

fn wait_ack(
    listeners: &Listeners,
    nonce: &[u8; 32],
    path: &Path,
    timeout: Duration,
) -> io::Result<()> {
    let start = Instant::now();
    loop {
        listeners
            .empty()
            .map_err(|_| diag::child_failure(diag::CHILD_ACK_LISTENER))?;
        match files::read(path) {
            Ok(bytes) => {
                protocol::check_receipt(&bytes, nonce, false)?;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && start.elapsed() < timeout => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(diag::child_failure(diag::CHILD_ACK_TIMEOUT));
            }
            Err(_) => return Err(diag::child_failure(diag::CHILD_ACK_READ)),
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
        let nonce = protocol::test_nonce();
        let missing = wait_ack(&listeners, &nonce, &path, Duration::from_millis(20)).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(missing.to_string(), diag::CHILD_ACK_TIMEOUT);
        std::fs::write(
            &path,
            protocol::receipt(&protocol::mismatched_nonce(nonce), false),
        )
        .unwrap();
        let wrong = wait_ack(&listeners, &nonce, &path, Duration::from_millis(20)).unwrap_err();
        assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(wrong.to_string(), "receipt nonce mismatch");
        std::fs::write(&path, protocol::receipt(&nonce, false)).unwrap();
        wait_ack(&listeners, &nonce, &path, Duration::from_millis(20)).unwrap();
    }
}
