//! Benchmark-only wrappers preserve the real signing and audit implementations.
use super::*;
use irmind_app::{AuditLog, CaseLock, CaseMutation, SignedOperation, Signer, Verifier};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct Timings {
    sign: AtomicU64,
    verify: AtomicU64,
    append: AtomicU64,
}
impl Timings {
    fn add(counter: &AtomicU64, started: Instant) {
        counter.fetch_add(
            u64::try_from(started.elapsed().as_nanos()).unwrap(),
            Ordering::Relaxed,
        );
    }
    pub(super) fn reset(&self) {
        for counter in [&self.sign, &self.verify, &self.append] {
            counter.store(0, Ordering::Relaxed);
        }
    }
    pub(super) fn report(&self) {
        let seconds = |n: &AtomicU64| Duration::from_nanos(n.load(Ordering::Relaxed)).as_secs_f64();
        println!(
            "CUSTODY_PHASE sign_seconds={:.6} verify_signature_seconds={:.6} append_seconds={:.6}",
            seconds(&self.sign),
            seconds(&self.verify),
            seconds(&self.append)
        );
    }
}
pub(super) fn attach(ports: &mut EnginePorts) -> Arc<Timings> {
    let timings = Arc::new(Timings::default());
    ports.signer = Arc::new(Sign {
        inner: ports.signer.clone(),
        timings: timings.clone(),
    });
    ports.verifier = Arc::new(Verify {
        inner: ports.verifier.clone(),
        timings: timings.clone(),
    });
    ports.audit_log = Arc::new(Log {
        inner: ports.audit_log.clone(),
        timings: timings.clone(),
    });
    timings
}
struct Sign {
    inner: Arc<dyn Signer>,
    timings: Arc<Timings>,
}
impl Signer for Sign {
    fn actor(&self) -> Actor {
        self.inner.actor()
    }
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        let started = Instant::now();
        let result = self.inner.sign(bytes);
        Timings::add(&self.timings.sign, started);
        result
    }
}
struct Verify {
    inner: Arc<dyn Verifier>,
    timings: Arc<Timings>,
}
impl Verifier for Verify {
    fn trusted_public_key(&self, actor: &Actor) -> Result<Vec<u8>, AppError> {
        self.inner.trusted_public_key(actor)
    }
    fn verify(&self, key: &[u8], bytes: &[u8], sig: &[u8]) -> Result<(), AppError> {
        let started = Instant::now();
        let result = self.inner.verify(key, bytes, sig);
        Timings::add(&self.timings.verify, started);
        result
    }
}
struct Log {
    inner: Arc<dyn AuditLog>,
    timings: Arc<Timings>,
}
impl AuditLog for Log {
    fn last_entry(&self, id: &CaseId) -> Result<Option<SignedEntry>, AppError> {
        self.inner.last_entry(id)
    }
    fn transact(&self, entry: &SignedEntry, mutation: CaseMutation) -> Result<(), AppError> {
        let started = Instant::now();
        let result = self.inner.transact(entry, mutation);
        Timings::add(&self.timings.append, started);
        result
    }
    fn append_batch(&self, entries: &[SignedEntry]) -> Result<(), AppError> {
        let started = Instant::now();
        let result = self.inner.append_batch(entries);
        Timings::add(&self.timings.append, started);
        result
    }
    fn entries(&self, id: &CaseId) -> Result<Vec<SignedEntry>, AppError> {
        self.inner.entries(id)
    }
    fn last_operation(&self, id: &CaseId) -> Result<Option<SignedOperation>, AppError> {
        self.inner.last_operation(id)
    }
    fn append_operation(&self, entry: &SignedOperation) -> Result<(), AppError> {
        self.inner.append_operation(entry)
    }
    fn operations(&self, id: &CaseId) -> Result<Vec<SignedOperation>, AppError> {
        self.inner.operations(id)
    }
    fn lock_global_operations(&self) -> Result<Box<dyn CaseLock>, AppError> {
        self.inner.lock_global_operations()
    }
    fn global_operations(&self) -> Result<Vec<SignedOperation>, AppError> {
        self.inner.global_operations()
    }
    fn append_global_operation(&self, entry: &SignedOperation) -> Result<(), AppError> {
        self.inner.append_global_operation(entry)
    }
}
