//! Exercise the original exclusive-producer/full-queue cycle without Parquet cost.
#![allow(clippy::unwrap_used)]
use super::*;
use std::sync::{Arc, Barrier, Mutex};

#[test]
fn a_later_exclusive_producer_cannot_hold_a_full_queue_ahead_of_the_first() {
    let cancel = CancellationToken::new();
    let lease = Arc::new(Mutex::new(()));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for source in 0..2 {
        let (start, permit) = permit(true);
        let (send, receive) = sync_channel(1);
        let operation = cancel.clone();
        let lease = lease.clone();
        let barrier = barrier.clone();
        let worker = std::thread::spawn(move || {
            barrier.wait();
            if source == 0 {
                std::thread::sleep(Duration::from_millis(30));
            }
            start.wait(&operation)?;
            send_under_exclusive_lease(&lease, &send, source, &operation)
        });
        workers.push((receive, worker, permit));
    }
    barrier.wait();
    let mut complete = true;
    for (receive, worker, permit) in workers {
        permit.release().unwrap();
        for expected in 0..3 {
            match receive.recv_timeout(Duration::from_secs(2)) {
                Ok((_, ordinal)) if ordinal == expected => {}
                _ => {
                    complete = false;
                    cancel.cancel();
                    break;
                }
            }
        }
        worker.join().unwrap().unwrap_or_else(|error| {
            assert!(cancel.is_cancelled(), "unexpected producer error: {error}");
        });
    }
    assert!(
        complete,
        "exclusive producer blocked behind a later full queue"
    );
}

fn send_under_exclusive_lease(
    lease: &Mutex<()>,
    send: &SyncSender<(usize, usize)>,
    source: usize,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let _lease = loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if let Ok(lease) = lease.try_lock() {
            break lease;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    for ordinal in 0..3 {
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            match send.try_send((source, ordinal)) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    return Err(AppError::Cancelled);
                }
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
    Ok(())
}
