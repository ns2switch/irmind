use irmind_app::subagents::EngineEventBatch;
use irmind_app::{CancellationToken, CaseId, Engine};
use std::{
    sync::mpsc,
    thread::{Scope, ScopedJoinHandle},
    time::Duration,
};

pub(super) struct EventFeed<'scope> {
    cancel: CancellationToken,
    worker: Option<ScopedJoinHandle<'scope, ()>>,
    pub(super) receiver: mpsc::Receiver<Result<EngineEventBatch, String>>,
}
impl<'scope> EventFeed<'scope> {
    pub(super) fn start<'env>(
        scope: &'scope Scope<'scope, 'env>,
        engine: &Engine<'_>,
        case: &CaseId,
        shutdown: &CancellationToken,
    ) -> Option<Self> {
        let (mut cursor, mut subscription) = engine.subscribe_case_events(case).ok()?;
        let cancel = shutdown.child_token();
        let signal = cancel.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = scope.spawn(move || {
            while !signal.is_cancelled() {
                let batch = match subscription.poll(cursor, 64, &signal) {
                    Ok(batch) => batch,
                    Err(irmind_app::AppError::Cancelled) => break,
                    Err(error) => {
                        let _sent = send(&sender, Err(error.to_string()), &signal);
                        break;
                    }
                };
                cursor = batch.next;
                let more = batch.more;
                if !batch.events.is_empty() && !send(&sender, Ok(batch), &signal) {
                    break;
                }
                if !more {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
        Some(Self {
            cancel,
            worker: Some(worker),
            receiver,
        })
    }
}
impl Drop for EventFeed<'_> {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
    }
}
fn send(
    sender: &mpsc::SyncSender<Result<EngineEventBatch, String>>,
    mut batch: Result<EngineEventBatch, String>,
    cancel: &CancellationToken,
) -> bool {
    while !cancel.is_cancelled() {
        match sender.try_send(batch) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
            Err(mpsc::TrySendError::Full(pending)) => batch = pending,
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}
