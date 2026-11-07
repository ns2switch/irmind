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
    AuditEventKind, Case, CaseId, CaseScope, GraphQueryFilter, IndexedInstant, IndexedTime,
    ParserSelectionMode, ProposedCall, Provenance, SealedParquetMigrationV1, Severity, SourceKind,
    SourceManifestV1, SourceManifestV2, TimePrecision, Tool,
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
mod definitions;
pub use definitions::{
    ApprovedDefinitions, DefinitionCompiler, DefinitionError, DefinitionStatus,
    MAX_DEFINITION_BYTES, ParserDefinitionStore,
};
pub mod common_event;
pub use common_event::{
    CommonGraphRecord, decode_common_event, encode_common_event, lift_unclassified_common,
    validate_common_record,
};
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
mod logical_source;
pub use logical_source::SourceParser;
mod ingest_options;
pub use ingest_options::{IngestOptions, command_time_context};
mod keystore;
mod large_case;
mod parser_calendar;
pub use parser_calendar::ParserCalendar;
mod parser_time;
mod parser_time_json;
mod parser_time_suggestions;
mod parser_warnings;
pub use parser_time::{
    ParserTimeBasis, ParserTimeContext, ParserTimeRequirement, ParserTimeSuggestion, parse_offset,
};
pub use parser_time_json::{ParserTimeFields, json_time_requirement};
pub use parser_warnings::{ParserExtractionWarning, parser_extraction_warning};
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
pub use ingest::{GraphRecord, GraphRelation, IndexedGraphRecord, TimelineEvent};
mod indexed_parser;
pub use indexed_parser::{IndexedProjection, indexed_rfc3339, parse_indexed_report};
pub use keystore::{KeystoreCapability, KeystoreManifest, SecretBackend, SignerBackend};
pub use large_case::{LargeCaseUseCases, ParserSelection, SourceCheckMode, SourceCheckReport};
mod partition_preparation;
pub use partition_preparation::{LocalBatchRequest, PartitionLimits, PartitionProfile};
pub use ports::*;
use ports::{isolate_untrusted, remote_tool_error, run_async, safe_markdown};
pub use report::{EntityDetails, Finding, FindingKind};

#[cfg(test)]
mod tests;

mod artifact_migration;
pub use artifact_migration::{
    ArtifactCatalog, ArtifactCatalogBuilder, ArtifactMigrationRequest, PreparedArtifactMigration,
    SealInventoryBuilder, artifact_catalog, seal_inventory, verify_seal_inventory_snapshot,
};
