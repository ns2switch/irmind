//! Bounded parse-start permits; initial source hashing remains concurrent.
use irmind_app::{AppError, CancellationToken};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::Duration;

pub(super) struct Start(Option<Receiver<()>>);
pub(super) struct Permit(Option<SyncSender<()>>);

pub(super) fn permit(serial: bool) -> (Start, Permit) {
    if serial {
        let (send, receive) = sync_channel(1);
        (Start(Some(receive)), Permit(Some(send)))
    } else {
        (Start(None), Permit(None))
    }
}
impl Start {
    pub(super) fn wait(self, cancel: &CancellationToken) -> Result<(), AppError> {
        let Some(receive) = self.0 else {
            return Ok(());
        };
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            match receive.recv_timeout(Duration::from_millis(10)) {
                Ok(()) => return Ok(()),
                Err(RecvTimeoutError::Disconnected) => return Err(AppError::Cancelled),
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}
impl Permit {
    pub(super) fn release(self) -> Result<(), AppError> {
        if let Some(send) = self.0 {
            send.try_send(()).map_err(|_| AppError::Cancelled)?;
        }
        Ok(())
    }
}

/// Stop siblings on errors or unwind, without cancelling the caller's token.
pub(super) struct Abort(pub(super) CancellationToken);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests;
