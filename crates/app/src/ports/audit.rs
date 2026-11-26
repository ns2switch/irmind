use crate::{
    Actor, AuditEventKind, CaseId, Deserialize, Digest, Error, FixedAppError,
    ParserTimeRequirement, ParserTimeSuggestion, Serialize, Sha256,
};
#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    CaseLifecycle(#[from] crate::CaseLifecycleError),
    #[error("skill package: {0}")]
    SkillPackage(#[from] irmind_domain::SkillError),
    #[error("skills: {0}")]
    SkillService(#[from] crate::SkillServiceError),
    #[error("source preparation rejected a file")]
    SourceFailure(crate::RejectedSource),
    #[error("direct group rejected {0} sources; the exclusion limit is 16; group rolled back")]
    SourceGroupExclusionLimit(usize),
    #[error(transparent)]
    Fixed(FixedAppError),
    #[error("module secret not found")]
    SecretMissing,
    #[error("operation cancelled")]
    Cancelled,
    #[error("remote tool execution failed")]
    RemoteTool,
    #[error("storage: {0}")]
    Storage(String),
    #[error("signature: {0}")]
    Signature(String),
    #[error("content guard: {0}")]
    Guard(String),
    #[error("model: {0}")]
    Model(String),
    #[error("policy denied: {0}")]
    Policy(String),
    #[error("policy denied: {0}")]
    SourceQuery(#[from] crate::source_queries::SourceQueryError),
    #[error(
        "Cloud transfer limit reached: {used} reserved bytes, {requested} requested, limit {limit}. Use /budget; the organization ceiling still applies."
    )]
    CloudTransferLimit {
        used: u64,
        requested: u64,
        limit: u64,
    },
    #[error("analyst approval required: {0}")]
    PendingApproval(String),
    #[error("parser {parser_id} is unavailable: {reason}")]
    ParserUnavailable { parser_id: String, reason: String },
    #[error(
        "The file is compressed with {format}. No available parser detected support for this compressed input."
    )]
    UnsupportedCompressedSource { format: &'static str },
    #[error("Recognized {kind}. Integrity files are skipped during event ingestion.")]
    NonEventSource {
        kind: crate::modules::NonEventSource,
    },
    #[error("analyst must choose a parser for the source")]
    ParserSelection {
        source_name: String,
        candidates: Vec<(String, u8)>,
    },
    #[error("the source needs an analyst-confirmed year and fixed UTC offset")]
    ParserTimeContextRequired {
        source_name: String,
        requirement: ParserTimeRequirement,
        suggestions: Vec<ParserTimeSuggestion>,
    },
    #[error("this source needs an analyst-confirmed cluster identity")]
    ParserClusterContextRequired {
        source_name: String,
        requirement: crate::ParserClusterRequirement,
    },
    #[error("this parser does not accept cluster context")]
    ParserClusterUnsupported,
    #[error("this parser does not accept a temporal context")]
    ParserTimeUnsupported,
    #[error("invalid case id")]
    InvalidCaseId,
    #[error("case is sealed")]
    Sealed,
    #[error("audit chain invalid at sequence {0}")]
    InvalidChain(u64),
    #[error("evidence hash mismatch: {0}")]
    EvidenceMismatch(String),
}

pub(crate) fn remote_tool_error(_error: AppError) -> AppError {
    AppError::RemoteTool
}

pub(crate) fn run_async<T>(
    future: impl std::future::Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| AppError::Storage(format!("async runtime: {error}")))?;
    runtime.block_on(future)
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SignedEntry {
    pub seq: u64,
    pub case_id: String,
    pub at: u64,
    #[serde(with = "actor_serde")]
    pub actor: Actor,
    pub origin: String,
    #[serde(with = "audit_kind_serde")]
    pub kind: AuditEventKind,
    pub payload: String,
    pub evidence: Option<String>,
    pub prev: [u8; 32],
    pub hash: [u8; 32],
    pub sig: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl std::fmt::Debug for SignedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedEntry")
            .field("seq", &self.seq)
            .field("case_id", &self.case_id)
            .field("kind", &self.kind)
            .field("hash", &hex(&self.hash))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct CaseSeal {
    pub seq: u64,
    pub hash: [u8; 32],
    pub sig: Vec<u8>,
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub analyst_key_fingerprint: String,
}

pub fn seal_challenge(
    case_id: &CaseId,
    seq: u64,
    final_hash: &[u8; 32],
    manifest: &str,
) -> Vec<u8> {
    let mut bytes = b"irmind-seal-v1\0".to_vec();
    put(&mut bytes, case_id.as_str().as_bytes());
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(final_hash);
    put(&mut bytes, manifest.as_bytes());
    bytes
}

impl SignedEntry {
    pub fn canonical(&self) -> Vec<u8> {
        let mut bytes = b"irmind-audit-v2\0".to_vec();
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        put(&mut bytes, self.case_id.as_bytes());
        bytes.extend_from_slice(&self.at.to_be_bytes());
        put(&mut bytes, self.actor.as_storage().as_bytes());
        put(&mut bytes, self.origin.as_bytes());
        put(&mut bytes, self.kind.as_str().as_bytes());
        put(&mut bytes, self.payload.as_bytes());
        match &self.evidence {
            Some(hash) => {
                bytes.push(1);
                put(&mut bytes, hash.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.prev);
        put(&mut bytes, &self.public_key);
        bytes
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SignedOperation {
    pub case_id: String,
    pub seq: u64,
    pub at: u64,
    #[serde(with = "actor_serde")]
    pub actor: Actor,
    pub operation: String,
    pub prev: [u8; 32],
    pub hash: [u8; 32],
    pub sig: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Reserved scope for installation-wide operations; no valid `CaseId` has this value.
pub const GLOBAL_OPERATION_SCOPE: &str = "global";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelledOperation {
    Ingest,
    GraphRebuild,
    Verify,
    Investigation,
    Approval,
    Export,
    Seal,
    EvidenceSave,
}

impl CancelledOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::GraphRebuild => "graph-rebuild",
            Self::Verify => "verify",
            Self::Investigation => "investigation",
            Self::Approval => "approval",
            Self::Export => "export",
            Self::Seal => "seal",
            Self::EvidenceSave => "evidence-save",
        }
    }
}

impl SignedOperation {
    pub fn canonical(&self) -> Vec<u8> {
        let mut bytes = b"irmind-operation-v1\0".to_vec();
        put(&mut bytes, self.case_id.as_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.at.to_be_bytes());
        put(&mut bytes, self.actor.as_storage().as_bytes());
        put(&mut bytes, self.operation.as_bytes());
        bytes.extend_from_slice(&self.prev);
        put(&mut bytes, &self.public_key);
        bytes
    }
}

mod actor_serde {
    use irmind_domain::Actor;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        actor: &Actor,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&actor.as_storage())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Actor, D::Error> {
        let value = String::deserialize(deserializer)?;
        Actor::parse_storage(&value).map_err(|_| serde::de::Error::custom("invalid actor"))
    }
}

mod audit_kind_serde {
    use irmind_domain::AuditEventKind;
    use serde::{Deserialize, Deserializer, Serializer};

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde with requires a borrowed field"
    )]
    pub(crate) fn serialize<S: Serializer>(
        kind: &AuditEventKind,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(kind.as_str())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AuditEventKind, D::Error> {
        let value = String::deserialize(deserializer)?;
        AuditEventKind::parse(&value)
            .map_err(|_| serde::de::Error::custom("unknown audit event kind"))
    }
}

fn put(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

pub(crate) fn safe_markdown(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control()
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        {
            safe.push(' ');
        } else if matches!(ch, '\\' | '<' | '>' | '[' | ']' | '*' | '_' | '#' | '`') {
            safe.push('\\');
            safe.push(ch);
        } else {
            safe.push(ch);
        }
    }
    safe
}

pub(crate) fn isolate_untrusted(value: &str, nonce: &uuid::Uuid) -> String {
    value
        .replace(&format!("</UNTRUSTED_{nonce}>"), "[ESCAPED_DELIMITER]")
        .replace(&format!("<UNTRUSTED_{nonce}>"), "[ESCAPED_DELIMITER]")
}

pub use irmind_mapping_contracts::{hex, sha256};

pub fn sha256_stream(visit: &mut irmind_domain::ByteStream<'_>) -> [u8; 32] {
    let mut state = Sha256::new();
    visit(&mut |bytes| state.update(bytes));
    state.finalize().into()
}
