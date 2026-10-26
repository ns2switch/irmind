#![deny(unsafe_code)]

mod clock;
mod evidence_fs;
mod graph_duckdb;
mod graph_port;
mod seal;
mod signing;
mod sqlite;
pub use clock::SystemClock;
use irmind_fs::{private_dir, private_file};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use fs4::fs_std::FileExt as _;
use irmind_app::{
    AppError, AuditLog, CancellationToken, CaseExporter, CaseLock, CaseMutation, CaseSeal,
    EventParser, EvidenceGraph, EvidenceStore, ExportVerifier, GLOBAL_OPERATION_SCOPE, GraphRecord,
    Repository, SignedEntry, SignedOperation, Signer, TimelineEvent, Verifier, hex, seal_challenge,
    sha256, verify_case_metadata,
};
use irmind_domain::{
    Actor, AnalystApprovalVerifier, Case, CaseId, Provenance, Severity, SourceKind, Tainted,
    valid_entity,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use graph_duckdb::GraphStore;

fn storage(_error: impl std::fmt::Display) -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
        irmind_app::AdapterStorageError::LocalStorageOperationFailed,
    ))
}

fn storage_reason(message: &'static str) -> AppError {
    AppError::Storage(message.into())
}

pub struct LocalStore {
    db: Mutex<Connection>,
    graph: GraphStore,
    evidence_dir: PathBuf,
    seal_dir: PathBuf,
    lock_dir: PathBuf,
}

struct HeldCaseFile {
    _file: fs::File,
}
impl CaseLock for HeldCaseFile {}

pub use seal::{LocalExportVerifier, verify_export, verify_export_expected};
use signing::verify_signature;
pub use signing::{LocalAnalystVerifier, LocalSigner, LocalVerifier};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::evidence_fs::read_evidence_file;
    use super::seal::MAX_EXPORT_BYTES;
    include!("tests/foundation.rs");
    include!("tests/test_support.rs");
    include!("tests/scope_and_graph.rs");
    include!("tests/case_findings_and_agent.rs");
    include!("tests/remote_dispatch_siem_cloud.rs");
    include!("tests/remote_dispatch_edr_ti.rs");
    include!("tests/injection_and_taint.rs");
    include!("tests/seal_export.rs");
    include!("tests/approvals.rs");
    include!("tests/concurrency_and_migrations.rs");
    include!("tests/graph_runtime.rs");
    include!("tests/custody_operations.rs");
}
