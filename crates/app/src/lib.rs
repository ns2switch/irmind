#![forbid(unsafe_code)]

pub mod modules;
pub mod tool_catalog;

pub use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use irmind_domain::{
    Actor, AnalystApprovalVerifier, AuditEventKind, AuthorizedCall, CaseScope, Decision,
    DeclassificationAuthority, ExecutionMode, PendingApproval, PolicyRules, ProposedCall,
    Provenance, SourceKind, Tainted, Tool, evaluate, evaluate_tainted,
};
pub use irmind_domain::{Case, CaseId, Severity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use thiserror::Error;
pub use tokio_util::sync::CancellationToken;

mod adapter_storage_errors;
mod approvals;
mod configuration;
mod custody;
mod dispatch;
mod engine;
pub use adapter_storage_errors::AdapterStorageError;
mod adapter_signature_errors;
pub use adapter_signature_errors::AdapterSignatureError;
mod adapter_guard_errors;
pub use adapter_guard_errors::AdapterGuardError;
mod adapter_model_errors;
pub use adapter_model_errors::AdapterModelError;
mod adapter_policy_errors;
pub use adapter_policy_errors::AdapterPolicyError;
mod fixed_errors;
mod ingest;
mod keystore;
mod ports;
pub use fixed_errors::FixedAppError;
mod report;

pub use approvals::ApprovalRequest;
pub use configuration::{
    ConfigChange, ConfigDifference, ConfigurationInspection, ConfigurationReview,
    ConfigurationStore, PersistentConfig, ProductSettings,
};
pub use custody::{SealPreview, export_case, verify_export};
pub use engine::{CryptoPorts, Engine, EnginePorts, verify_case_metadata};
pub use ingest::{GraphRecord, GraphRelation, TimelineEvent};
pub use keystore::{KeystoreCapability, KeystoreManifest, SecretBackend, SignerBackend};
pub use ports::*;
use ports::{isolate_untrusted, remote_tool_error, run_async, safe_markdown};
pub use report::{Finding, FindingKind};

#[cfg(test)]
mod tests;
