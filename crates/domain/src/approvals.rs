use crate::{
    BTreeMap, Case, CaseId, DomainError, ExecutionMode, Tool, canonical_args, put, take_field,
    take_u64,
};
use sha2::{Digest as _, Sha256};

#[derive(Clone)]
pub struct ProposedCall {
    pub tool: Tool,
    pub args: BTreeMap<String, String>,
}

impl std::fmt::Debug for ProposedCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProposedCall")
            .field("tool", &self.tool)
            .field("argument_count", &self.args.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizedCall {
    pub(crate) case_id: CaseId,
    pub(crate) proposal: ProposedCall,
    pub(crate) decision_seq: u64,
}

impl AuthorizedCall {
    pub fn case_id(&self) -> &CaseId {
        &self.case_id
    }
    pub fn tool(&self) -> &Tool {
        &self.proposal.tool
    }
    pub fn arg(&self, key: &str) -> Option<&str> {
        self.proposal.args.get(key).map(String::as_str)
    }
    pub fn proposal_args(&self) -> &BTreeMap<String, String> {
        &self.proposal.args
    }
    pub fn decision_seq(&self) -> u64 {
        self.decision_seq
    }
}

#[derive(Debug)]
pub enum Decision {
    Allow(AuthorizedCall),
    Deny(&'static str),
    NeedsApproval(PendingApproval),
}

#[derive(Debug)]
pub struct PendingApproval {
    case_id: CaseId,
    proposal: ProposedCall,
    decision_seq: u64,
    expires_at: u64,
}

pub trait AnalystApprovalVerifier {
    fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool;
}

impl PendingApproval {
    pub(crate) fn new(
        case_id: CaseId,
        proposal: ProposedCall,
        decision_seq: u64,
        now: u64,
    ) -> Self {
        let expires_at = now.saturating_add(300);
        Self {
            case_id,
            proposal,
            decision_seq,
            expires_at,
        }
    }

    pub fn recover(
        case: &Case,
        mode: ExecutionMode,
        encoded: &[u8],
        now: u64,
    ) -> Result<Self, DomainError> {
        Self::recover_with_rules(case, mode, encoded, now, &crate::PolicyRules::default())
    }

    pub fn recover_with_rules(
        case: &Case,
        mode: ExecutionMode,
        encoded: &[u8],
        now: u64,
        rules: &crate::PolicyRules,
    ) -> Result<Self, DomainError> {
        let mut rest = encoded
            .strip_prefix(b"irmind-approval-v2\0")
            .ok_or(DomainError::InvalidApproval)?;
        let case_id = std::str::from_utf8(take_field(&mut rest)?)
            .map_err(|_| DomainError::InvalidApproval)?;
        if case_id != case.id.as_str() {
            return Err(DomainError::InvalidApproval);
        }
        let decision_seq = take_u64(&mut rest)?;
        let name = std::str::from_utf8(take_field(&mut rest)?)
            .map_err(|_| DomainError::InvalidApproval)?;
        let tool = Tool::parse(name)?;
        let count = take_u64(&mut rest)?;
        if count > 16 {
            return Err(DomainError::InvalidApproval);
        }
        let mut args = BTreeMap::new();
        for _ in 0..count {
            let key = std::str::from_utf8(take_field(&mut rest)?)
                .map_err(|_| DomainError::InvalidApproval)?;
            let value = std::str::from_utf8(take_field(&mut rest)?)
                .map_err(|_| DomainError::InvalidApproval)?;
            if key.len() > 64
                || value.len() > 1024
                || args.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(DomainError::InvalidApproval);
            }
        }
        let claimed_hash = rest.get(..32).ok_or(DomainError::InvalidApproval)?;
        if claimed_hash != Sha256::digest(canonical_args(&args)).as_slice() {
            return Err(DomainError::InvalidApproval);
        }
        rest = &rest[32..];
        let expires_at = take_u64(&mut rest)?;
        if !rest.is_empty() {
            return Err(DomainError::InvalidApproval);
        }
        let mut open = case.clone();
        open.sealed = false;
        let Decision::NeedsApproval(mut pending) = crate::evaluate_with_rules(
            &open,
            ProposedCall { tool, args },
            decision_seq,
            mode,
            now,
            rules,
        ) else {
            return Err(DomainError::InvalidApproval);
        };
        pending.expires_at = expires_at;
        if pending.challenge() != encoded {
            return Err(DomainError::InvalidApproval);
        }
        Ok(pending)
    }
    pub fn proposal(&self) -> &ProposedCall {
        &self.proposal
    }

    pub fn decision_seq(&self) -> u64 {
        self.decision_seq
    }

    pub fn challenge(&self) -> Vec<u8> {
        let mut bytes = b"irmind-approval-v2\0".to_vec();
        put(&mut bytes, self.case_id.as_str().as_bytes());
        bytes.extend_from_slice(&self.decision_seq.to_be_bytes());
        put(&mut bytes, self.proposal.tool.as_str().as_bytes());
        let args = canonical_args(&self.proposal.args);
        bytes.extend_from_slice(&args);
        bytes.extend_from_slice(&Sha256::digest(&args));
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes
    }

    pub fn resolve(
        self,
        signature: &[u8],
        verifier: &dyn AnalystApprovalVerifier,
        now: u64,
    ) -> Result<AuthorizedCall, DomainError> {
        if now > self.expires_at || !verifier.verify_analyst(&self.challenge(), signature) {
            return Err(DomainError::InvalidApproval);
        }
        Ok(AuthorizedCall {
            case_id: self.case_id,
            proposal: self.proposal,
            decision_seq: self.decision_seq,
        })
    }

    pub fn rejection_challenge(&self) -> Vec<u8> {
        let mut bytes = self.challenge();
        bytes.extend_from_slice(b"\0deny");
        bytes
    }

    pub fn reject(
        self,
        signature: &[u8],
        verifier: &dyn AnalystApprovalVerifier,
    ) -> Result<(), DomainError> {
        if !verifier.verify_analyst(&self.rejection_challenge(), signature) {
            return Err(DomainError::InvalidApproval);
        }
        Ok(())
    }
}
