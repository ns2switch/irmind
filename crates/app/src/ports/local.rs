use crate::{
    Actor, AppError, CancellationToken, Case, CaseId, CaseSeal, GraphRecord, SignedEntry,
    SignedOperation, Tainted, TimelineEvent,
};
use irmind_domain::{ParquetArtifactV1, SourceManifestV1};
use std::io::Read;
use std::path::Path;
pub trait CaseLock: Send {}

pub trait Repository: Send + Sync {
    fn lock_case(&self, id: &CaseId) -> Result<Box<dyn CaseLock>, AppError>;
    fn get_case(&self, id: &CaseId) -> Result<Case, AppError>;
    fn list_cases(&self) -> Result<Vec<Case>, AppError>;
    fn write_seal_file(&self, id: &CaseId, seal: &CaseSeal) -> Result<(), AppError>;
    fn case_seal(&self, id: &CaseId) -> Result<Option<CaseSeal>, AppError>;
}

pub trait EvidenceStore: Send + Sync {
    fn put_evidence(&self, id: &CaseId, hash: &str, bytes: &[u8]) -> Result<(), AppError>;
    fn get_evidence(&self, id: &CaseId, hash: &str) -> Result<Vec<u8>, AppError>;
    fn evidence_hashes(&self, id: &CaseId) -> Result<Vec<String>, AppError>;
    fn search_evidence(
        &self,
        id: &CaseId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<String>, AppError>;
}

pub trait EvidenceGraph: Send + Sync {
    fn index_from_parser(
        &self,
        id: &CaseId,
        hash: &str,
        source: &str,
        bytes: &[u8],
        parser: &dyn EventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError>;
    fn index_records(
        &self,
        id: &CaseId,
        hash: &str,
        records: &[Tainted<GraphRecord>],
        cancel: &CancellationToken,
    ) -> Result<(), AppError>;
    fn graph_version(&self) -> &'static str;
    fn graph_summary(&self, id: &CaseId) -> Result<String, AppError>;
    fn timeline(&self, id: &CaseId, limit: usize) -> Result<Vec<TimelineEvent>, AppError>;
    fn entity_lookup(&self, id: &CaseId, kind: &str, value: &str) -> Result<String, AppError>;
    fn neighbors(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError>;
    fn entity_timeline(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError>;
    fn graph_path(
        &self,
        id: &CaseId,
        from: (&str, &str),
        to: (&str, &str),
    ) -> Result<String, AppError>;
    fn text_search(&self, id: &CaseId, query: &str, limit: usize) -> Result<String, AppError>;
    fn raw_record(&self, id: &CaseId, hash: &str, index: usize) -> Result<String, AppError>;
    fn rebuild_graph(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        parser: &dyn EventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError>;
    fn verify_graph(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        parser: &dyn EventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError>;
}

pub enum CaseMutation {
    None,
    Create(Case),
    Scope { id: CaseId, new_scope: String },
    Seal(CaseId),
}

pub trait AuditLog: Send + Sync {
    fn last_entry(&self, id: &CaseId) -> Result<Option<SignedEntry>, AppError>;
    fn transact(&self, entry: &SignedEntry, mutation: CaseMutation) -> Result<(), AppError>;
    /// Append-only events use the same transaction path without a case-state mutation.
    fn append(&self, entry: &SignedEntry) -> Result<(), AppError> {
        self.transact(entry, CaseMutation::None)
    }
    fn entries(&self, id: &CaseId) -> Result<Vec<SignedEntry>, AppError>;
    fn last_operation(&self, id: &CaseId) -> Result<Option<SignedOperation>, AppError>;
    fn append_operation(&self, entry: &SignedOperation) -> Result<(), AppError>;
    fn operations(&self, id: &CaseId) -> Result<Vec<SignedOperation>, AppError>;
    fn lock_global_operations(&self) -> Result<Box<dyn CaseLock>, AppError>;
    fn global_operations(&self) -> Result<Vec<SignedOperation>, AppError>;
    fn append_global_operation(&self, entry: &SignedOperation) -> Result<(), AppError>;
}

pub trait EventParser: Send + Sync {
    fn version(&self) -> &'static str;
    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError>;

    fn parse(&self, source: &str, bytes: &[u8]) -> Result<Vec<Tainted<GraphRecord>>, AppError> {
        let mut records = Vec::new();
        self.parse_each(source, bytes, &CancellationToken::new(), &mut |record| {
            records.push(record);
            Ok(())
        })?;
        Ok(records)
    }
}

/// Parser for large, pre-hashed sources. The caller verifies the same reader
/// again while parsing before it commits any signed manifest entry.
pub trait StreamingEventParser: Send + Sync {
    fn streaming_version(&self) -> &'static str;
    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        evidence_hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError>;
}

pub struct PreparedSource {
    pub manifest: SourceManifestV1,
    pub artifacts: Vec<ParquetArtifactV1>,
    pub records: usize,
}

/// The local adapter owns all paths and derived files. The application signs
/// the returned manifests before any derived file is exposed to model tools.
pub trait LargeCaseStore: Send + Sync {
    fn prepare_local(
        &self,
        case_id: &CaseId,
        source_root: &Path,
        relative_path: &str,
        copy_original: bool,
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<PreparedSource, AppError>;

    fn prepare_legacy_evidence(
        &self,
        case_id: &CaseId,
        hash: &str,
        bytes: &[u8],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<Vec<ParquetArtifactV1>, AppError>;

    fn compact_artifacts(
        &self,
        case_id: &CaseId,
        sources: &[ParquetArtifactV1],
        cancel: &CancellationToken,
    ) -> Result<ParquetArtifactV1, AppError>;

    fn verify_local_source(
        &self,
        source_root: &Path,
        manifest: &SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError>;

    fn verify_copied_source(
        &self,
        case_id: &CaseId,
        manifest: &SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError>;

    fn verify_artifact(
        &self,
        case_id: &CaseId,
        artifact: &ParquetArtifactV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError>;

    fn rebuild_compare(
        &self,
        case_id: &CaseId,
        source_root: &Path,
        sources: &[SourceManifestV1],
        artifacts: &[ParquetArtifactV1],
        parser: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError>;
}

pub trait Signer: Send + Sync {
    fn actor(&self) -> Actor;
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError>;
}

pub trait Verifier: Send + Sync {
    fn trusted_public_key(&self, actor: &Actor) -> Result<Vec<u8>, AppError>;
    fn verify(&self, public_key: &[u8], message: &[u8], sig: &[u8]) -> Result<(), AppError>;
}

pub trait ExportVerifier: Send + Sync {
    fn verify_export(
        &self,
        path: &Path,
        expected_key: Option<&str>,
    ) -> Result<(String, usize), AppError>;

    fn verify_export_details(
        &self,
        path: &Path,
        expected_key: Option<&str>,
    ) -> Result<ExportVerification, AppError> {
        let (analyst_key_fingerprint, entries) = self.verify_export(path, expected_key)?;
        Ok(ExportVerification {
            analyst_key_fingerprint,
            entries,
            format_version: 3,
            source_manifests: 0,
            source_bytes_verified: 0,
            source_bytes_unavailable: 0,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportVerification {
    pub analyst_key_fingerprint: String,
    pub entries: usize,
    pub format_version: u32,
    pub source_manifests: usize,
    pub source_bytes_verified: usize,
    pub source_bytes_unavailable: usize,
}

pub trait LargeCaseExporter: Send + Sync {
    fn export_case_v4(
        &self,
        id: &CaseId,
        path: &Path,
        source_root: Option<&Path>,
        include_originals: bool,
        cancel: &CancellationToken,
    ) -> Result<String, AppError>;
}

/// Writes a sealed case package to a new local path. The application verifies
/// the signed case before invoking this port. Implementations must never
/// overwrite an existing path and must remove incomplete output on error.
pub trait CaseExporter: Send + Sync {
    fn export_case(
        &self,
        id: &CaseId,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<String, AppError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, AppError>;
}

pub struct Screened {
    pub text: String,
    pub detections: Vec<String>,
}

pub trait ContentGuard: Send + Sync {
    fn fingerprint(&self) -> String;
    fn self_test(&self) -> Result<(), AppError>;
    fn screen(&self, input: &str) -> Result<Screened, AppError>;
}

pub fn startup_check(guard: &dyn ContentGuard) -> Result<(), AppError> {
    guard.self_test()
}
