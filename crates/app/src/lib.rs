#![forbid(unsafe_code)]

pub mod modules;
pub mod tool_catalog;

pub use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
pub use irmind_domain::CaseId;
use irmind_domain::{
    Actor, AnalystApprovalVerifier, AuthorizedCall, Case, CaseScope, Decision,
    DeclassificationAuthority, ExecutionMode, PendingApproval, PolicyRules, ProposedCall,
    Provenance, Severity, SourceKind, Tainted, Tool, evaluate, evaluate_tainted,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use thiserror::Error;
pub use tokio_util::sync::CancellationToken;

mod approvals;
mod custody;
mod dispatch;
mod engine;
mod ingest;
mod ports;
mod report;

pub use approvals::ApprovalRequest;
pub use engine::{CryptoPorts, Engine, EnginePorts, verify_case_metadata};
pub use ingest::{GraphRecord, GraphRelation, TimelineEvent};
pub use ports::*;
use ports::{isolate_untrusted, remote_tool_error, run_async, safe_markdown};
pub use report::{Finding, FindingKind};

#[cfg(test)]
mod tests;
