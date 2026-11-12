//! One bounded job per lane; output frames are acknowledged after ordered commit.
use super::super::{AppError, CancellationToken, invalid_source};
use std::{
    sync::mpsc::{self, Receiver, SyncSender},
    thread::{Scope, ScopedJoinHandle},
    time::Duration,
};
enum Frame<O> {
    Item(O),
    End,
    Error(AppError),
}
pub(super) struct OrderedPool<'scope, I, O> {
    jobs: Vec<SyncSender<I>>,
    results: Vec<Receiver<Frame<O>>>,
    acknowledgements: Vec<SyncSender<()>>,
    threads: Vec<ScopedJoinHandle<'scope, ()>>,
    submitted: usize,
    consumed: usize,
}
impl<'scope, I: Send + 'scope, O: Send + 'scope> OrderedPool<'scope, I, O> {
    pub(super) fn new<'env>(
        scope: &'scope Scope<'scope, 'env>,
        lanes: usize,
        prepare: &'scope (
                    impl Fn(I, &mut dyn FnMut(O) -> Result<(), AppError>) -> Result<(), AppError> + Sync
                ),
    ) -> Result<Self, AppError> {
        let mut pool = Self {
            jobs: vec![],
            results: vec![],
            acknowledgements: vec![],
            threads: vec![],
            submitted: 0,
            consumed: 0,
        };
        for _ in 0..lanes {
            pool.add_lane(scope, prepare)?;
        }
        Ok(pool)
    }
    fn add_lane<'env>(
        &mut self,
        scope: &'scope Scope<'scope, 'env>,
        prepare: &'scope (
                    impl Fn(I, &mut dyn FnMut(O) -> Result<(), AppError>) -> Result<(), AppError> + Sync
                ),
    ) -> Result<(), AppError> {
        let (send, receive) = mpsc::sync_channel(1);
        let (result_send, result_receive) = mpsc::sync_channel(1);
        let (ack_send, ack_receive) = mpsc::sync_channel(1);
        self.jobs.push(send);
        self.results.push(result_receive);
        self.acknowledgements.push(ack_send);
        self.threads.push(
            std::thread::Builder::new()
                .spawn_scoped(scope, move || {
                    while let Ok(input) = receive.recv() {
                        let result = prepare(input, &mut |output| {
                            result_send
                                .send(Frame::Item(output))
                                .map_err(|_| invalid_source())?;
                            // No next output can be prepared while this one is retained by
                            // the coordinator. This also bounds oversized single records.
                            ack_receive.recv().map_err(|_| invalid_source())
                        });
                        let frame = result.map_or_else(Frame::Error, |()| Frame::End);
                        if result_send.send(frame).is_err() {
                            break;
                        }
                    }
                })
                .map_err(|_| invalid_source())?,
        );
        Ok(())
    }
    pub(super) fn submit(
        &mut self,
        input: I,
        cancel: &CancellationToken,
        emit: &mut impl FnMut(O) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        if self.submitted - self.consumed == self.jobs.len() {
            self.next(cancel, emit)?;
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.jobs[self.submitted % self.jobs.len()]
            .send(input)
            .map_err(|_| invalid_source())?;
        self.submitted += 1;
        Ok(())
    }
    fn next(
        &mut self,
        cancel: &CancellationToken,
        emit: &mut impl FnMut(O) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        let lane = self.consumed % self.results.len();
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            match self.results[lane].recv_timeout(Duration::from_millis(10)) {
                Ok(Frame::Item(value)) => {
                    emit(value)?;
                    self.acknowledgements[lane]
                        .send(())
                        .map_err(|_| invalid_source())?;
                }
                Ok(Frame::End) => {
                    self.consumed += 1;
                    return Ok(());
                }
                Ok(Frame::Error(error)) => return Err(error),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(invalid_source()),
            }
        }
    }
    pub(super) fn finish(
        &mut self,
        cancel: &CancellationToken,
        emit: &mut impl FnMut(O) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        while self.consumed < self.submitted {
            self.next(cancel, emit)?;
        }
        Ok(())
    }
}
impl<I, O> Drop for OrderedPool<'_, I, O> {
    fn drop(&mut self) {
        // Disconnect acknowledgements and both payload directions before joins.
        self.acknowledgements.clear();
        self.jobs.clear();
        self.results.clear();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn results_commit_in_submission_order_at_every_worker_limit() {
        for lanes in [1, 2, 4, 7] {
            let cancel = CancellationToken::new();
            let mut actual = Vec::new();
            let job = |n: usize, emit: &mut dyn FnMut(usize) -> Result<(), AppError>| {
                if n.is_multiple_of(3) {
                    std::thread::yield_now();
                }
                emit(n * n)?;
                emit(n * n + 1)
            };
            std::thread::scope(|scope| {
                let mut pool = OrderedPool::new(scope, lanes, &job).unwrap();
                let mut commit = |v| {
                    actual.push(v);
                    Ok(())
                };
                for n in 0..257 {
                    pool.submit(n, &cancel, &mut commit).unwrap();
                }
                pool.finish(&cancel, &mut commit).unwrap();
            });
            assert_eq!(
                actual,
                (0..257)
                    .flat_map(|n| [n * n, n * n + 1])
                    .collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn callback_error_and_cancellation_disconnect_pending_results() {
        for cancelled in [false, true] {
            let cancel = CancellationToken::new();
            let job = |n: usize, emit: &mut dyn FnMut(usize) -> Result<(), AppError>| emit(n);
            std::thread::scope(|scope| {
                let mut pool = OrderedPool::new(scope, 4, &job).unwrap();
                for n in 0..4 {
                    pool.submit(n, &cancel, &mut |_| Ok(())).unwrap();
                }
                if cancelled {
                    cancel.cancel();
                }
                assert!(matches!(
                    pool.finish(&cancel, &mut |_| Err(AppError::Cancelled)),
                    Err(AppError::Cancelled)
                ));
            });
        }
    }
    #[test]
    fn failed_worker_is_a_pipeline_error() {
        let cancel = CancellationToken::new();
        let job = |_, _: &mut dyn FnMut(usize) -> Result<(), AppError>| Err(invalid_source());
        std::thread::scope(|scope| {
            let mut pool = OrderedPool::new(scope, 2, &job).unwrap();
            pool.submit(0, &cancel, &mut |_| Ok(())).unwrap();
            assert!(pool.finish(&cancel, &mut |_| Ok(())).is_err());
        });
    }
}
