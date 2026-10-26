#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use crossterm::event::KeyCode;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CaseLock, CaseSeal, CompletionRequest,
    ConfigurationStore, CryptoPorts, Engine, EnginePorts, EvidenceStore, LlmPort, ModelResponse,
    ModelStream, Repository, Signer, ThreatIntelPort, single_completion_stream,
};
#[cfg(feature = "keystore-file")]
use irmind_app::{KeystoreCapability, KeystoreManifest, SecretBackend, SignerBackend};
use irmind_domain::{
    Actor, AuthorizedCall, Case, CaseId, ExecutionMode, ProposedCall, Severity, Tool,
};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
#[cfg(feature = "keystore-file")]
use irmind_mod_keystore_file::FileKeystore;
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use irmind_tui::{
    ModuleKind, ModuleParameter, ModuleSelectionSource, ModuleStatus, WorkspaceIo,
    scripted::{ScriptedWorkspace, render_keystore_setup},
};
use ratatui::{Terminal, backend::TestBackend};
#[cfg(feature = "keystore-file")]
use secrecy::{ExposeSecret as _, SecretString};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[allow(clippy::wildcard_imports)]
#[path = "tui_case/support.rs"]
mod support;
#[allow(clippy::wildcard_imports)]
#[path = "tui_case/workflows.rs"]
mod workflows;
