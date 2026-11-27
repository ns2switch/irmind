use crate::{
    Actor, AnalystApprovalVerifier, BTreeMap, Deserialize, ExecutionMode, Provenance, Serialize,
    Tool, Verifier,
};

#[derive(Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub tool: Tool,
    pub args: BTreeMap<String, String>,
    pub mode: ExecutionMode,
    pub decision_seq: u64,
    pub(crate) challenge: Vec<u8>,
}

#[derive(Clone)]
pub struct ApprovalSource {
    pub provenance: Provenance,
    pub source_label: String,
    pub excerpt: String,
}

impl std::fmt::Debug for ApprovalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalSource")
            .field("provenance", &self.provenance)
            .field("source_label_bytes", &self.source_label.len())
            .field("excerpt_bytes", &self.excerpt.len())
            .finish()
    }
}

impl std::fmt::Debug for ApprovalRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalRequest")
            .field("id", &self.id)
            .field("tool", &self.tool)
            .field("decision_seq", &self.decision_seq)
            .field("argument_count", &self.args.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingEvent {
    pub(crate) version: u8,
    pub(crate) id: String,
    pub(crate) mode: String,
    pub(crate) decision_seq: u64,
    pub(crate) tool: String,
    pub(crate) args: BTreeMap<String, String>,
    pub(crate) challenge: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ApprovalEvent {
    pub(crate) version: u8,
    pub(crate) id: String,
    pub(crate) signature: String,
    pub(crate) reason: Option<String>,
    pub(crate) executed: bool,
}

struct AnalystVerifierAdapter<'a>(&'a dyn Verifier);

impl AnalystApprovalVerifier for AnalystVerifierAdapter<'_> {
    fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool {
        self.0
            .trusted_public_key(&Actor::Analyst)
            .is_ok_and(|key| self.0.verify(&key, message, signature).is_ok())
    }
}

pub(crate) mod gui;
mod request;
mod resolution;
mod scope;
mod source;
mod task;
