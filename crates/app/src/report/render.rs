use super::{EntityDetails, Finding, FindingKind};
use crate::{AppError, CaseId, Engine, safe_markdown};
use std::fmt::Write as _;

impl Engine<'_> {
    pub fn report(&self, id: &CaseId) -> Result<String, AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        let case = self.repo.get_case(id)?;
        let findings = self.findings_unlocked(id, &self.audit_log.entries(id)?)?;
        let mut report = format!(
            "# IRMind incident report\n\nCase: {}\n\nTitle: {}\n\nSeverity: {}\n\nScope: {}\n\n",
            id.as_str(),
            safe_markdown(&case.title),
            case.severity.as_str(),
            safe_markdown(&case.scope)
        );
        let confirmed_count = findings.iter().filter(|finding| finding.confirmed).count();
        let _ = writeln!(
            report,
            "## Summary\n\n{confirmed_count} analyst-confirmed findings with evidence links.\n"
        );
        report.push_str("## Timeline\n\n");
        for finding in findings
            .iter()
            .filter(|finding| finding.confirmed && finding.kind == FindingKind::Timeline)
        {
            if let Some(EntityDetails::Timeline {
                at,
                source,
                record_index,
            }) = &finding.details
            {
                let pointer = record_index.map_or_else(String::new, |index| format!("#{index}"));
                let _ = writeln!(
                    report,
                    "- {} — {}: {} [evidence: {}{}]",
                    safe_markdown(at),
                    safe_markdown(source),
                    safe_markdown(&finding.value),
                    finding.evidence_hash,
                    pointer
                );
            }
        }
        for kind in [
            FindingKind::Ioc,
            FindingKind::Hypothesis,
            FindingKind::Technique,
            FindingKind::Impact,
            FindingKind::Recommendation,
        ] {
            let _ = write!(report, "\n## {}\n\n", kind.heading());
            for finding in findings
                .iter()
                .filter(|finding| finding.confirmed && finding.kind == kind)
            {
                let _ = writeln!(report, "{}", render_confirmed(finding));
            }
        }
        Ok(report)
    }
}

fn render_confirmed(finding: &Finding) -> String {
    let value = safe_markdown(&finding.value);
    match &finding.details {
        Some(EntityDetails::Ioc {
            ioc_type,
            first_seen,
            last_seen,
            verdict,
        }) => format!(
            "- {value} ({ioc_type}; first seen {first_seen}; last seen {last_seen}; verdict {verdict}) [evidence: {}]",
            finding.evidence_hash
        ),
        Some(EntityDetails::Hypothesis {
            supporting_evidence,
            refuting_evidence,
        }) => {
            let supporting = if supporting_evidence.is_empty() {
                finding.evidence_hash.clone()
            } else {
                supporting_evidence.join(", ")
            };
            if refuting_evidence.is_empty() {
                format!("- {value} [supporting evidence: {supporting}]")
            } else {
                format!(
                    "- {value} [supporting evidence: {supporting}; refuting evidence: {}]",
                    refuting_evidence.join(", ")
                )
            }
        }
        _ => format!("- {value} [evidence: {}]", finding.evidence_hash),
    }
}
