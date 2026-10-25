use crate::*;

#[derive(Debug, Error)]
pub enum AppError {
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
    #[error("analyst approval required: {0}")]
    PendingApproval(String),
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
    pub kind: String,
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
        put(&mut bytes, self.kind.as_bytes());
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

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

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
}

pub trait EventParser: Send + Sync {
    fn version(&self) -> &'static str;
    fn parse(&self, source: &str, bytes: &[u8]) -> Result<Vec<Tainted<GraphRecord>>, AppError>;
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

pub struct ModelResponse {
    pub text: String,
    pub calls: Vec<ProposedCall>,
    pub raw: String,
}

impl std::fmt::Debug for ModelResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelResponse")
            .field("text_bytes", &self.text.len())
            .field("call_count", &self.calls.len())
            .field("raw_bytes", &self.raw.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ModelPricing {
    pub input_microusd_per_million: u64,
    pub output_microusd_per_million: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageEvent {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost_microusd: Option<u64>,
}

pub fn summarize_usage(entries: &[SignedEntry]) -> Result<UsageEvent, AppError> {
    let mut total = UsageEvent {
        input_tokens: 0,
        output_tokens: 0,
        estimated_cost_microusd: None,
    };
    for entry in entries.iter().filter(|entry| entry.kind == "ModelUsage") {
        let usage: UsageEvent =
            serde_json::from_str(&entry.payload).map_err(|_| AppError::InvalidChain(entry.seq))?;
        total.input_tokens = total
            .input_tokens
            .checked_add(usage.input_tokens)
            .ok_or(AppError::InvalidChain(entry.seq))?;
        total.output_tokens = total
            .output_tokens
            .checked_add(usage.output_tokens)
            .ok_or(AppError::InvalidChain(entry.seq))?;
        if let Some(cost) = usage.estimated_cost_microusd {
            total.estimated_cost_microusd = Some(
                total
                    .estimated_cost_microusd
                    .unwrap_or(0)
                    .checked_add(cost)
                    .ok_or(AppError::InvalidChain(entry.seq))?,
            );
        }
    }
    Ok(total)
}

pub type ModelStream = std::pin::Pin<Box<dyn Stream<Item = Result<ModelEvent, AppError>> + Send>>;

#[derive(Debug)]
pub enum ModelEvent {
    Progress(usize),
    Completed {
        response: ModelResponse,
        usage: Option<ModelUsage>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone)]
pub struct CompletionMessage {
    pub role: MessageRole,
    pub content: String,
}

impl std::fmt::Debug for CompletionMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CompletionRequest {
    pub messages: Vec<CompletionMessage>,
    pub tools: Vec<tool_catalog::ToolSpec>,
    pub max_output_tokens: u32,
    pub remaining_case_tokens: u64,
}

impl std::fmt::Debug for CompletionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionRequest")
            .field("message_count", &self.messages.len())
            .field("tool_count", &self.tools.len())
            .field("max_output_tokens", &self.max_output_tokens)
            .field("remaining_case_tokens", &self.remaining_case_tokens)
            .finish()
    }
}

impl CompletionRequest {
    pub fn context(&self) -> Option<&str> {
        self.messages
            .iter()
            .rev()
            .find(|message| message.role == MessageRole::User)
            .map(|message| message.content.as_str())
    }
}

#[async_trait]
pub trait LlmPort: Send + Sync {
    fn descriptor(&self) -> String {
        "unspecified".into()
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError>;
}

pub async fn collect_model_stream(
    mut events: ModelStream,
    cancel: &CancellationToken,
) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
    let mut completed = None;
    loop {
        let event = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            event = events.next() => event,
        };
        let Some(event) = event else { break };
        match event? {
            ModelEvent::Progress(_) if completed.is_none() => {}
            ModelEvent::Completed { response, usage } if completed.is_none() => {
                completed = Some((response, usage));
            }
            _ => {
                return Err(AppError::Model(
                    "provider emitted data after completion".into(),
                ));
            }
        }
    }
    completed.ok_or_else(|| AppError::Model("provider stream ended without completion".into()))
}

pub fn single_completion_stream(response: ModelResponse, usage: Option<ModelUsage>) -> ModelStream {
    Box::pin(futures_util::stream::once(async move {
        Ok(ModelEvent::Completed { response, usage })
    }))
}

#[async_trait]
pub trait ThreatIntelPort: Send + Sync {
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait SiemPort: Send + Sync {
    fn source_id(&self) -> &str;
    fn dialect(&self) -> &'static str;
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait CloudAuditPort: Send + Sync {
    fn source_id(&self) -> &str;
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait EdrPort: Send + Sync {
    fn source_id(&self) -> &str;
    fn supports(&self, tool: &Tool) -> bool;
    fn process_tree_hint(&self) -> Option<&'static str> {
        None
    }
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait InternalIntelPort: Send + Sync {
    fn source_id(&self) -> &str;
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}
