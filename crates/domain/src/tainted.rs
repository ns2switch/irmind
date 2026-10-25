use crate::{CaseId, DomainError};

/// Data that originated outside the trusted case and policy boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct Tainted<T> {
    pub(crate) value: T,
    provenance: Provenance,
}

impl<T> std::fmt::Debug for Tainted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tainted")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    File,
    ToolResult,
    Graph,
    ModelProposal,
    AnalystInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    evidence_hash: [u8; 32],
    record_index: Option<u64>,
    source_kind: SourceKind,
}

impl Provenance {
    pub fn new(
        evidence_hash: [u8; 32],
        record_index: Option<u64>,
        source_kind: SourceKind,
    ) -> Self {
        Self {
            evidence_hash,
            record_index,
            source_kind,
        }
    }

    pub fn evidence_hash(&self) -> &[u8; 32] {
        &self.evidence_hash
    }
    pub fn record_index(&self) -> Option<u64> {
        self.record_index
    }
    pub fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    pub fn approval_challenge(&self, case_id: &CaseId) -> Vec<u8> {
        let mut out = b"irmind-declassify-v1\0".to_vec();
        out.extend_from_slice(case_id.as_str().as_bytes());
        out.push(0);
        out.extend_from_slice(&self.evidence_hash);
        out.extend_from_slice(&self.record_index.unwrap_or(u64::MAX).to_be_bytes());
        out.push(self.source_kind as u8);
        out
    }
}

pub trait DeclassificationAuthority {
    fn verify_and_audit(&self, challenge: &[u8], signature: &[u8], provenance: &Provenance)
    -> bool;
}

impl<T> Tainted<T> {
    pub fn from_external(value: T, provenance: Provenance) -> Self {
        Self { value, provenance }
    }

    /// Permits local processing without returning an untainted value.
    pub fn inspect(&self, visitor: impl FnOnce(&T)) {
        visitor(&self.value);
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn release_with_approval(
        self,
        case_id: &CaseId,
        signature: &[u8],
        authority: &dyn DeclassificationAuthority,
    ) -> Result<T, DomainError> {
        let challenge = self.provenance.approval_challenge(case_id);
        if !authority.verify_and_audit(&challenge, signature, &self.provenance) {
            return Err(DomainError::InvalidApproval);
        }
        Ok(self.value)
    }
}
