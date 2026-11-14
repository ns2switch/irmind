//! Session-local source capabilities and independently bounded original reads.
mod authority;
mod replay;
mod signed;
use crate::LocalStore;
use authority::Authority;
use irmind_app::{AppError, CancellationToken, SourceEvidenceReader};
use irmind_domain::{CaseId, EvidenceHash, SourceRecordV1, Tainted};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) struct OriginalReader {
    store: Arc<LocalStore>,
    authority: Mutex<Authority>,
    busy: Arc<AtomicBool>,
}

impl LocalStore {
    pub fn source_evidence_reader(self: &Arc<Self>) -> Arc<dyn SourceEvidenceReader> {
        Arc::new(OriginalReader {
            store: Arc::clone(self),
            authority: Mutex::new(Authority::default()),
            busy: Arc::new(AtomicBool::new(false)),
        })
    }
}

fn unavailable(reason: &'static str) -> AppError {
    AppError::Policy(reason.into())
}

struct ReadPermit(Arc<AtomicBool>);
impl Drop for ReadPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl SourceEvidenceReader for OriginalReader {
    fn authorize_local_root(
        &self,
        case: &CaseId,
        root: &Path,
        hashes: &[EvidenceHash],
    ) -> Result<(), AppError> {
        self.authorize(case, root, hashes)
    }

    fn read_verified_record(
        &self,
        case: &CaseId,
        hash: &EvidenceHash,
        index: u64,
        cancel: &CancellationToken,
    ) -> Result<Tainted<SourceRecordV1>, AppError> {
        self.read_with_deadline(case, hash, index, cancel, Duration::from_secs(10))
    }
}

impl OriginalReader {
    fn read_with_deadline(
        &self,
        case: &CaseId,
        hash: &EvidenceHash,
        index: u64,
        cancel: &CancellationToken,
        budget: Duration,
    ) -> Result<Tainted<SourceRecordV1>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if index >= 100_000 {
            return Err(unavailable("invalid original record pointer"));
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                unavailable("An original-record read is still stopping; retry after it finishes")
            })?;
        let permit = ReadPermit(Arc::clone(&self.busy));
        let deadline = Instant::now() + budget;
        let snapshot = self
            .authority
            .lock()
            .map_err(crate::storage)?
            .snapshot(case, hash);
        let job = replay::ReadJob {
            store: Arc::clone(&self.store),
            case: case.clone(),
            hash: hash.clone(),
            index,
            root: snapshot.root,
            cancel: cancel.child_token(),
        };
        let worker_cancel = job.cancel.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("irmind-source-read".into())
            .spawn(move || {
                let result = job.run();
                // A completed read must release its slot before its caller can retry.
                drop(permit);
                let _ = send.send(result);
            })
            .map_err(|_| unavailable("Original-record worker could not start; retry"))?;
        let result = wait(&receive, cancel, deadline);
        worker_cancel.cancel();
        let state = self.authority.lock().map_err(crate::storage)?;
        if !state.matches(case, snapshot.generation) {
            return Err(unavailable(
                "The active case changed; original-record read cancelled",
            ));
        }
        result
    }
}

fn wait<T>(
    receive: &std::sync::mpsc::Receiver<Result<T, AppError>>,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<T, AppError> {
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(unavailable(
                "Original-record read exceeded 10 seconds; no original was returned",
            ));
        }
        match receive.recv_timeout(remaining.min(Duration::from_millis(20))) {
            Ok(result) => {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(unavailable(
                        "Original-record deadline exceeded; no original was returned",
                    ));
                }
                return result;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(unavailable(
                    "Original-record decoder stopped; no original was returned",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
