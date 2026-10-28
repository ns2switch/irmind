#![forbid(unsafe_code)]

//! Shared, offline contract suites for product adapters.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use irmind_app::{
    AppError, CancellationToken, Clock, CloudAuditPort, CompletionMessage, CompletionRequest,
    EdrPort, InternalIntelPort, KeystoreCapability, LlmPort, MessageRole, SecretBackend, SiemPort,
    SignerBackend, ThreatIntelPort, collect_model_stream,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{
    Actor, AnalystApprovalVerifier, AuthorizedCall, Case, CaseId, Decision, ExecutionMode,
    ProposedCall, Severity, Tool, evaluate,
};
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

mod contract_support;
mod edr_contract;
mod fakes;
mod keystore_contract;
mod mock_http;
mod product_contracts;

pub use edr_contract::{EdrFixture, EdrScenario, run_edr_contract};
pub use fakes::{FROM, FakeEdr, FixedClock, HOST, OUTSIDE, TO};
pub use keystore_contract::{secret_backend_contract, signer_backend_contract};
pub use mock_http::{MockResponse, MockServer, RecordedRequest, run_http_safety_contract};
pub use product_contracts::{
    run_cloud_audit_contract, run_cloud_audit_recorded, run_internal_intel_contract,
    run_internal_intel_recorded, run_llm_contract, run_siem_alert_recorded, run_siem_contract,
    run_siem_recorded, run_threat_intel_contract, run_threat_intel_recorded,
};
