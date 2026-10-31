#![forbid(unsafe_code)]

pub mod modules;
pub mod tool_catalog;

pub use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use irmind_domain::{
    Actor, AnalystApprovalVerifier, AuthorizedCall, Decision, DeclassificationAuthority,
    ExecutionMode, PendingApproval, PolicyRules, Tainted,
};
pub use irmind_domain::{
    AuditEventKind, Case, CaseId, CaseScope, GraphQueryFilter, ParserSelectionMode, ProposedCall,
    Provenance, SealedParquetMigrationV1, Severity, SourceKind, SourceManifestV1, Tool,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use thiserror::Error;
pub use tokio_util::sync::CancellationToken;

mod adapter_storage_errors;
mod approvals;
mod audit_origin;
mod configuration;
mod custody;
mod diagnostics;
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
mod large_case;
mod ports;
pub use fixed_errors::FixedAppError;
mod report;

pub use approvals::{ApprovalRequest, ApprovalSource};
use audit_origin::AuditOrigin;
pub use configuration::{
    ConfigChange, ConfigDifference, ConfigurationInspection, ConfigurationReview,
    ConfigurationStore, PersistentConfig, ProductSettings,
};
pub use custody::{SealPreview, export_case, export_case_v4, verify_export, verify_export_details};
pub use engine::{CryptoPorts, Engine, EnginePorts, verify_case_metadata};
pub use ingest::{GraphRecord, GraphRelation, TimelineEvent};
pub use keystore::{KeystoreCapability, KeystoreManifest, SecretBackend, SignerBackend};
pub use large_case::{LargeCaseUseCases, ParserSelection, SourceCheckMode, SourceCheckReport};
pub use ports::*;
use ports::{isolate_untrusted, remote_tool_error, run_async, safe_markdown};
pub use report::{EntityDetails, Finding, FindingKind};

#[cfg(test)]
mod tests;
