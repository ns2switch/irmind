use super::PreparedInvestigation;
use crate::{
    Actor, AppError, AuditEventKind, AuditOrigin, CaseId, CompletionMessage, Engine, MessageRole,
    SignedEntry,
};

impl Engine<'_> {
    pub(super) fn prepare_investigation_local(
        &self,
        id_owned: &CaseId,
        alert_owned: &str,
        descriptor: &str,
    ) -> Result<PreparedInvestigation, AppError> {
        let case = self.repo.get_case(id_owned)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id_owned)?;
        let entries = self.audit_log.entries(id_owned)?;
        let history = self.conversation_history(&entries)?;
        let findings = self
            .findings_unlocked(id_owned, &entries)?
            .into_iter()
            .filter(|finding| finding.confirmed && !finding.dismissed)
            .map(|finding| {
                format!(
                    "{:?}: {} [{}]",
                    finding.kind, finding.value, finding.evidence_hash
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let findings = self
            .screen_and_audit(id_owned, &findings, "ConfirmedFindings", None)?
            .text;
        self.audit_investigation_start(id_owned, alert_owned, descriptor)?;
        let screened =
            self.screen_and_audit(id_owned, alert_owned, AuditEventKind::Prompt.as_str(), None)?;
        let title = self.screen_and_audit(id_owned, &case.title, "CaseTitle", None)?;
        let scope = self.screen_and_audit(id_owned, &case.scope, "CaseScope", None)?;
        let timeline_text = self
            .graph
            .timeline(id_owned, 20)?
            .iter()
            .map(|event| {
                format!(
                    "{} {} [{}#{}]",
                    event.at, event.event, event.evidence_hash, event.record_index
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let timeline = self.screen_and_audit(id_owned, &timeline_text, "Timeline", None)?;
        Ok(PreparedInvestigation {
            case,
            screened,
            title,
            scope,
            timeline,
            findings,
            history,
        })
    }

    fn audit_investigation_start(
        &self,
        id: &CaseId,
        prompt: &str,
        descriptor: &str,
    ) -> Result<(), AppError> {
        for (kind, value) in [
            (AuditEventKind::GuardActivated, self.guard.fingerprint()),
            (
                AuditEventKind::PolicyActivated,
                self.policy_fingerprint.clone(),
            ),
            (
                AuditEventKind::ModulesActivated,
                self.module_fingerprint.clone(),
            ),
            (AuditEventKind::ModelSelected, descriptor.to_owned()),
        ] {
            self.audit(id, AuditOrigin::System, kind, &value, None)?;
        }
        let origin = match self.signer.actor() {
            Actor::Analyst => AuditOrigin::Analyst,
            Actor::Agent(_) => AuditOrigin::Agent,
        };
        self.audit(id, origin, AuditEventKind::Prompt, prompt, None)
    }

    fn conversation_history(
        &self,
        entries: &[SignedEntry],
    ) -> Result<Vec<CompletionMessage>, AppError> {
        let after_summary = entries
            .iter()
            .rposition(|entry| entry.kind == AuditEventKind::ConversationSummary);
        let mut history = Vec::new();
        if let Some(index) = after_summary {
            let summary = self.guard.screen(&entries[index].payload)?.text;
            history.push(CompletionMessage::text(
                MessageRole::System,
                format!("Prior conversation summary (UNTRUSTED): {summary}"),
            ));
        }
        let start = after_summary.map_or(0, |index| {
            entries[..index]
                .iter()
                .enumerate()
                .rev()
                .filter(|(_, entry)| {
                    matches!(
                        entry.kind,
                        AuditEventKind::Prompt | AuditEventKind::FinalAnswer
                    )
                })
                .take(8)
                .last()
                .map_or(index + 1, |(at, _)| at)
        });
        for entry in entries.iter().skip(start) {
            let role = match entry.kind {
                AuditEventKind::Prompt => MessageRole::User,
                AuditEventKind::FinalAnswer => MessageRole::Assistant,
                _ => continue,
            };
            let screened = self.guard.screen(&entry.payload)?.text;
            history.push(CompletionMessage::text(role, screened));
        }
        Ok(history)
    }
}
