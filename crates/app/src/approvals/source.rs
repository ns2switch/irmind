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
            if let Some((excerpt, record)) = matching_excerpt(text, request) {
                let decoded = hex::decode(hash).map_err(|_| AppError::InvalidChain(entry.seq))?;
                let hash_bytes: [u8; 32] = decoded
                    .try_into()
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                return Ok(ApprovalSource {
                    provenance: Provenance::new(
                        hash_bytes,
                        Some(record),
                        if entry.kind == AuditEventKind::ToolResult {
                            SourceKind::ToolResult
                        } else {
                            SourceKind::File
                        },
                    ),
                    source_label: entry.payload.clone(),
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
            source_label: "model proposal".into(),
            excerpt: self
                .screen_and_audit(id, &proposal, "ApprovalSource", None)?
                .text,
        })
    }
}

fn matching_excerpt(text: &str, request: &ApprovalRequest) -> Option<(String, u64)> {
    let match_at = request
        .args
        .iter()
        .filter(|(key, value)| {
            !matches!(key.as_str(), "source" | "from" | "to") && (4..=256).contains(&value.len())
        })
        .find_map(|(_, value)| text.find(value).map(|at| (at, value.len())))?;
    let start = text[..match_at.0].rfind('\n').map_or(0, |at| at + 1);
    let record = text[..start].bytes().filter(|byte| *byte == b'\n').count() as u64;
    let end = text[match_at.0..]
        .find('\n')
        .map_or(text.len(), |at| match_at.0 + at);
    if end.saturating_sub(start) > 16_384 {
        return Some((
            "The matching record is too long to display safely. Open the original with /evidence."
                .into(),
            record,
        ));
    }
    Some((text[start..end].to_owned(), record))
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
        let excerpt = matching_excerpt(&text, &request).unwrap_or_default().0;
        assert!(excerpt.contains("example.org"));
        assert_eq!(excerpt, text);
    }

    #[test]
    fn matching_excerpt_keeps_complete_json_record_line() {
        let request = ApprovalRequest {
            id: "synthetic".into(),
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.org".into())]),
            mode: ExecutionMode::Attended,
            decision_seq: 1,
            challenge: Vec::new(),
        };
        let line = r#"{"detail":{"ioc":"example.org","source":"synthetic"}}"#;
        assert_eq!(
            matching_excerpt(&format!("before\n{line}\nafter"), &request),
            Some((line.into(), 1))
        );
    }
}
