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
            services: Services::new().map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "EVTX requires running BFE and MpsSvc services with query and notification access"))?,
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
        let result = self.ensure_stable(program, cancelled);
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    fn ensure_stable(
        &self,
        program: &Arc<Prepared>,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Stamp> {
        // A service notification invalidates this attempt, never the invariant.
        // Repeat the complete witness with the new stamp before allowing input.
        for _ in 0..3 {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let stamp = self.services.snapshot()?;
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
            if self.services.snapshot()? != stamp {
                continue;
            }
            *self.verified.lock().map_err(|_| denied())? = Some(stamp);
            return Ok(stamp);
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "EVTX WFP service stamp did not stabilize across three complete witnesses",
        ))
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
