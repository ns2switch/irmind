use super::{ApprovalRequest, ApprovalSource};
use crate::{AppError, AuditEventKind, CaseId, Engine, Provenance, SourceKind, sha256};

impl Engine<'_> {
    /// Find a bounded, guarded evidence excerpt that contains a proposed value.
    /// This is a display hint, not authorization evidence or a taint release.
    pub fn approval_source(
        &self,
        id: &CaseId,
        request: &ApprovalRequest,
    ) -> Result<ApprovalSource, AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        let case = self.repo.get_case(id)?;
        let entries = self.audit_log.entries(id)?;
        if !self
            .pending_requests_unlocked(&case, &entries)?
            .iter()
            .any(|pending| pending.id == request.id)
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyPendingApprovalNotFound,
            ));
        }
        for entry in entries
            .iter()
            .rev()
            .filter(|entry| {
                entry.seq < request.decision_seq
                    && matches!(
                        entry.kind,
                        AuditEventKind::EvidenceIngested | AuditEventKind::ToolResult
                    )
            })
            .take(8)
        {
            let Some(hash) = &entry.evidence else {
                continue;
            };
            let raw = self.evidence_store.get_evidence(id, hash)?;
            if raw.len() > 10_000_000 {
                continue;
            }
            let Ok(text) = std::str::from_utf8(&raw) else {
                continue;
            };
            if let Some(excerpt) = matching_excerpt(text, request) {
                let decoded = hex::decode(hash).map_err(|_| AppError::InvalidChain(entry.seq))?;
                let hash_bytes: [u8; 32] = decoded
                    .try_into()
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                return Ok(ApprovalSource {
                    provenance: Provenance::new(
                        hash_bytes,
                        None,
                        if entry.kind == AuditEventKind::ToolResult {
                            SourceKind::ToolResult
                        } else {
                            SourceKind::File
                        },
                    ),
                    excerpt: self
                        .screen_and_audit(id, &excerpt, "ApprovalSource", Some(hash))?
                        .text,
                });
            }
        }
        let proposal = format!("{} {:?}", request.tool.as_str(), request.args);
        Ok(ApprovalSource {
            provenance: Provenance::new(
                sha256(proposal.as_bytes()),
                None,
                SourceKind::ModelProposal,
            ),
            excerpt: self
                .screen_and_audit(id, &proposal, "ApprovalSource", None)?
                .text,
        })
    }
}

fn matching_excerpt(text: &str, request: &ApprovalRequest) -> Option<String> {
    let match_at = request
        .args
        .iter()
        .filter(|(key, value)| {
            !matches!(key.as_str(), "source" | "from" | "to") && (4..=256).contains(&value.len())
        })
        .find_map(|(_, value)| text.find(value).map(|at| (at, value.len())))?;
    let mut start = match_at.0.saturating_sub(80);
    let mut end = text
        .len()
        .min(match_at.0.saturating_add(match_at.1).saturating_add(80));
    while !text.is_char_boundary(start) {
        start += 1;
    }
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Some(text[start..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionMode, Tool};
    use std::collections::BTreeMap;

    #[test]
    fn excerpt_is_bounded_and_uses_exact_argument_bytes() {
        let request = ApprovalRequest {
            id: "synthetic".into(),
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.org".into())]),
            mode: ExecutionMode::Attended,
            decision_seq: 1,
            challenge: Vec::new(),
        };
        let text = format!("{}example.org{}", "a".repeat(500), "b".repeat(500));
        let excerpt = matching_excerpt(&text, &request).unwrap_or_default();
        assert!(excerpt.contains("example.org"));
        assert!(excerpt.len() <= 171);
    }
}
