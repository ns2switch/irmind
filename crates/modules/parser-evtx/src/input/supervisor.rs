//! Own the child on an independent thread so consumer backpressure cannot stop its deadline.
use super::super::bad;
use irmind_app::{AppError, CancellationToken};
use irmind_process_containment::Child;
use std::{
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

enum Stop {
    Finish,
    Abort,
}
pub(super) struct Supervisor {
    stop: Sender<Stop>,
    thread: Option<JoinHandle<Result<(), AppError>>>,
}
impl Supervisor {
    pub(super) fn new(
        child: Child,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> Result<Self, AppError> {
        let (stop, receive) = mpsc::channel();
        let cancel = cancel.clone();
        let thread = thread::Builder::new()
            .name("evtx-deadline".into())
            .spawn(move || supervise(child, &receive, deadline, &cancel))
            .map_err(|_| bad("EVTX supervisor cannot start; entire file rejected"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
    pub(super) fn finish(&mut self, success: bool) -> Result<(), AppError> {
        let _ = self
            .stop
            .send(if success { Stop::Finish } else { Stop::Abort });
        self.thread
            .take()
            .ok_or_else(|| bad("EVTX supervisor unavailable"))?
            .join()
            .map_err(|_| bad("EVTX supervisor failed; entire file rejected"))?
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.stop.send(Stop::Abort);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
trait Process: Send {
    fn inspect(&mut self) -> Result<Option<bool>, AppError>;
    fn terminate(&mut self);
    fn unsuccessful(&mut self) -> AppError;
}
impl Process for Child {
    fn inspect(&mut self) -> Result<Option<bool>, AppError> {
        self.try_wait()
            .map_err(|_| bad("cannot inspect EVTX helper exit; entire file rejected"))
    }
    fn terminate(&mut self) {
        let _ = Child::terminate(self);
    }
    fn unsuccessful(&mut self) -> AppError {
        AppError::Policy(format!(
            "EVTX helper exited unsuccessfully ({}); entire file rejected; no partial ingestion",
            self.exit_description()
                .ok()
                .flatten()
                .unwrap_or_else(|| "exit status unavailable".into())
        ))
    }
}
fn supervise<P: Process>(
    mut child: P,
    receive: &Receiver<Stop>,
    deadline: Duration,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let start = Instant::now();
    let mut finishing = false;
    let result = loop {
        if start.elapsed() >= deadline {
            cancel.cancel();
            let bound = if deadline.subsec_nanos() == 0 {
                format!("{} s", deadline.as_secs())
            } else {
                format!("{} ms", deadline.as_millis())
            };
            break Err(AppError::Policy(format!(
                "EVTX invocation time limit reached ({bound}); entire file rejected; no partial ingestion"
            )));
        }
        if cancel.is_cancelled() {
            break Err(AppError::Cancelled);
        }
        match child.inspect() {
            Ok(Some(true)) if finishing => break Ok(()),
            Ok(Some(false)) if finishing => break Err(child.unsuccessful()),
            Err(error) => break Err(error),
            _ => {}
        }
        match receive.recv_timeout(Duration::from_millis(10)) {
            Ok(Stop::Finish) => finishing = true,
            Ok(Stop::Abort) | Err(RecvTimeoutError::Disconnected) => break Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
    };
    if result.is_err() {
        cancel.cancel();
    }
    child.terminate();
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct BlockedChild(Arc<AtomicBool>);
    impl Process for BlockedChild {
        fn inspect(&mut self) -> Result<Option<bool>, AppError> {
            Ok(None)
        }
        fn terminate(&mut self) {
            self.0.store(true, Ordering::Release);
        }
        fn unsuccessful(&mut self) -> AppError {
            bad("synthetic failure")
        }
    }
    #[test]
    fn deadline_terminates_child_while_record_callback_is_blocked() {
        let cancel = CancellationToken::new();
        let terminated = Arc::new(AtomicBool::new(false));
        let (hold, receive) = mpsc::channel();
        let (done, result) = mpsc::channel();
        let child = BlockedChild(terminated.clone());
        let operation = cancel.clone();
        let worker = thread::spawn(move || {
            let outcome = supervise(child, &receive, Duration::from_millis(30), &operation);
            done.send(outcome).unwrap();
        });
        // The callback cannot return until the independent watchdog cancels it.
        let start = Instant::now();
        while !cancel.is_cancelled() && start.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            cancel.is_cancelled(),
            "blocked callback stopped the deadline"
        );
        assert!(
            result
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("30 ms")
        );
        assert!(terminated.load(Ordering::Acquire));
        drop(hold);
        worker.join().unwrap();
    }
}
