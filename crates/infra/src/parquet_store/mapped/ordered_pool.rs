//! One outstanding item per lane, consumed in submission order.
use super::super::{AppError, CancellationToken, invalid_source};
use std::{
    sync::mpsc::{self, Receiver, SyncSender},
    thread::{Scope, ScopedJoinHandle},
    time::Duration,
};

pub(super) struct OrderedPool<'scope, I, O> {
    jobs: Vec<SyncSender<I>>,
    results: Vec<Receiver<Result<O, AppError>>>,
    threads: Vec<ScopedJoinHandle<'scope, ()>>,
    submitted: usize,
    consumed: usize,
}
impl<'scope, I: Send + 'scope, O: Send + 'scope> OrderedPool<'scope, I, O> {
    pub(super) fn new<'env>(
        scope: &'scope Scope<'scope, 'env>,
        lanes: usize,
        prepare: &'scope (impl Fn(I) -> Result<O, AppError> + Sync),
    ) -> Result<Self, AppError> {
        let mut pool = Self {
            jobs: vec![],
            results: vec![],
            threads: vec![],
            submitted: 0,
            consumed: 0,
        };
        for _ in 0..lanes {
            let (send, receive) = mpsc::sync_channel(1);
            let (result_send, result_receive) = mpsc::sync_channel(1);
            pool.jobs.push(send);
            pool.results.push(result_receive);
            pool.threads.push(
                std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        while let Ok(input) = receive.recv() {
                            if result_send.send(prepare(input)).is_err() {
                                break;
                            }
                        }
                    })
                    .map_err(|_| invalid_source())?,
            );
        }
        Ok(pool)
    }
    pub(super) fn submit(
        &mut self,
        input: I,
        cancel: &CancellationToken,
        emit: &mut impl FnMut(O) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        if self.submitted - self.consumed == self.jobs.len() {
            emit(self.next(cancel)?)?;
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
    fn next(&mut self, cancel: &CancellationToken) -> Result<O, AppError> {
        let receive = &self.results[self.consumed % self.results.len()];
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            match receive.recv_timeout(Duration::from_millis(10)) {
                Ok(value) => {
                    self.consumed += 1;
                    return value;
                }
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
            emit(self.next(cancel)?)?;
        }
        Ok(())
    }
}
impl<I, O> Drop for OrderedPool<'_, I, O> {
    fn drop(&mut self) {
        // Disconnect both directions before joining: a failed callback or an early
        // cancellation must never leave a worker blocked on a result channel.
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
            let job = |n| {
                if n % 3 == 0 {
                    std::thread::yield_now();
                }
                Ok(n * n)
            };
            std::thread::scope(|scope| {
                let mut pool = OrderedPool::new(scope, lanes, &job).unwrap();
                for n in 0..257 {
                    pool.submit(n, &cancel, &mut |v| {
                        actual.push(v);
                        Ok(())
                    })
                    .unwrap();
                }
                pool.finish(&cancel, &mut |v| {
                    actual.push(v);
                    Ok(())
                })
                .unwrap();
            });
            assert_eq!(actual, (0..257).map(|n| n * n).collect::<Vec<_>>());
        }
    }
    #[test]
    fn callback_error_and_cancellation_disconnect_pending_results() {
        for cancelled in [false, true] {
            let cancel = CancellationToken::new();
            let job = |n| Ok(n);
            std::thread::scope(|scope| {
                let mut pool = OrderedPool::new(scope, 4, &job).unwrap();
                for n in 0..4 {
                    pool.submit(n, &cancel, &mut |_| Ok(())).unwrap();
                }
                if cancelled {
                    cancel.cancel();
                }
                let result = pool.finish(&cancel, &mut |_| Err(AppError::Cancelled));
                assert!(matches!(result, Err(AppError::Cancelled)));
            });
        }
    }
    #[test]
    fn failed_worker_is_a_pipeline_error() {
        let cancel = CancellationToken::new();
        let job = |_| Err::<usize, _>(invalid_source());
        std::thread::scope(|scope| {
            let mut pool = OrderedPool::new(scope, 2, &job).unwrap();
            pool.submit(0, &cancel, &mut |_| Ok(())).unwrap();
            assert!(pool.finish(&cancel, &mut |_| Ok(())).is_err());
        });
    }
}
