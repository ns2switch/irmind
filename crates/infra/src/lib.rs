#![deny(unsafe_code)]

mod clock;
mod evidence_fs;
mod graph_duckdb;
mod graph_port;
mod private_fs;
mod seal;
mod signing;
mod sqlite;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_security;
pub use clock::SystemClock;
pub use private_fs::private_file;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use fs4::fs_std::FileExt as _;
use irmind_app::{
    AppError, AuditLog, CaseLock, CaseMutation, CaseSeal, EventParser, EvidenceGraph,
    EvidenceStore, ExportVerifier, GraphRecord, Repository, SignedEntry, SignedOperation, Signer,
    TimelineEvent, Verifier, hex, seal_challenge, sha256, verify_case_metadata,
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
    AppError::Storage("local storage operation failed".into())
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
    include!("tests/part1.rs");
    include!("tests/part2.rs");
    include!("tests/part3.rs");
    include!("tests/part4.rs");
    include!("tests/part5.rs");
    include!("tests/part6.rs");
    include!("tests/part7.rs");
}
