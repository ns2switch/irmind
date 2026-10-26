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

include!("keystore_contract.rs");
include!("fakes.rs");
include!("edr_contract.rs");
include!("product_contracts.rs");
include!("mock_http.rs");
