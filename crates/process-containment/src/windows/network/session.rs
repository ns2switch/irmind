#![cfg(windows)]
use super::{
    exchange,
    services::{Services, Stamp},
};
use crate::{WitnessStats, launch::Prepared, witness_protocol::denied};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
pub(crate) struct Session {
    services: Services,
    verified: Mutex<Option<Stamp>>,
    busy: Arc<AtomicBool>,
    poisoned: AtomicBool,
    attempts: AtomicU64,
    nanos: AtomicU64,
}
pub(crate) struct Lease(Arc<AtomicBool>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Session {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            services: Services::new()?,
            verified: Mutex::new(None),
            busy: Arc::new(AtomicBool::new(false)),
            poisoned: AtomicBool::new(false),
            attempts: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
        })
    }
    pub(crate) fn acquire(&self, cancelled: &dyn Fn() -> bool) -> io::Result<Lease> {
        loop {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.poisoned.load(Ordering::Acquire) {
                return Err(denied());
            }
            if self
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Lease(self.busy.clone()));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    pub(crate) fn ensure(
        &self,
        program: &Arc<Prepared>,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Stamp> {
        let result = (|| {
            let stamp = self.services.snapshot().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "EVTX WFP services are unavailable before the witness",
                )
            })?;
            if *self.verified.lock().map_err(|_| denied())? == Some(stamp) {
                return Ok(stamp);
            }
            self.invalidate();
            self.attempts.fetch_add(1, Ordering::Relaxed);
            let start = Instant::now();
            let result = exchange::verify(program, cancelled);
            self.nanos.fetch_add(
                u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            result?;
            if self.services.snapshot().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "EVTX WFP services are unavailable after the witness",
                )
            })? != stamp
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "EVTX WFP service stamp changed during the witness",
                ));
            }
            *self.verified.lock().map_err(|_| denied())? = Some(stamp);
            Ok(stamp)
        })();
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    pub(crate) fn unchanged(&self, stamp: Stamp) -> io::Result<()> {
        if self.services.snapshot()? == stamp {
            Ok(())
        } else {
            self.invalidate();
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "EVTX WFP service stamp changed before or after decoding",
            ))
        }
    }
    pub(crate) fn invalidate(&self) {
        if let Ok(mut verified) = self.verified.lock() {
            *verified = None;
        }
    }
    pub(crate) fn poison(&self) {
        self.invalidate();
        self.poisoned.store(true, Ordering::Release);
    }
    pub(crate) fn stats(&self) -> WitnessStats {
        WitnessStats {
            attempts: self.attempts.load(Ordering::Relaxed),
            elapsed: Duration::from_nanos(self.nanos.load(Ordering::Relaxed)),
        }
    }
}
pub(crate) type ServiceStamp = Stamp;
