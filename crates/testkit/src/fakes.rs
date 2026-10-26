use crate::{
    AppError, Arc, AtomicU64, AuthorizedCall, CancellationToken, Clock, EdrPort, Module,
    ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry, Mutex, Ordering, Tool,
};

pub const HOST: &str = "host-1";
pub const FROM: &str = "2026-10-23T12:00:00Z";
pub const TO: &str = "2026-10-23T13:00:00Z";
pub const OUTSIDE: &str = "2026-10-23T14:00:00Z";

pub struct FixedClock(AtomicU64);

impl FixedClock {
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Result<u64, AppError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

/// In-memory EDR for application tests. The manifest exposes only detections.
pub struct FakeEdr {
    source_id: String,
    host: String,
    evidence: Vec<u8>,
    calls: Arc<Mutex<usize>>,
}

static FAKE_EDR_MANIFEST: ModuleManifest = ModuleManifest {
    id: "edr-testkit",
    version: "0.1.0",
    ports: &[ModulePort::Edr],
    tools: &[Tool::EdrDetections],
    config: &[],
};

impl FakeEdr {
    #[must_use]
    pub fn new(source_id: &str, host: &str, evidence: Vec<u8>, calls: Arc<Mutex<usize>>) -> Self {
        Self {
            source_id: source_id.into(),
            host: host.into(),
            evidence,
            calls,
        }
    }
}

impl Module for FakeEdr {
    fn manifest(&self) -> &'static ModuleManifest {
        &FAKE_EDR_MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_edr(self)
    }
}

#[irmind_app::async_trait]
impl EdrPort for FakeEdr {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn supports(&self, tool: &Tool) -> bool {
        tool == &Tool::EdrDetections
    }
    async fn execute(
        &self,
        call: &AuthorizedCall,
        _cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::EdrDetections
            || call.arg("source") != Some(self.source_id())
            || call.arg("host") != Some(self.host.as_str())
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::FakeEDRSourceHostOrToolMismatch,
            )));
        }
        *self.calls.lock().map_err(|_| {
            AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::FakeEDRCounterPoisoned,
            ))
        })? += 1;
        Ok(self.evidence.clone())
    }
}
