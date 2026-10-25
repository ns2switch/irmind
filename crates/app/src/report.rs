use crate::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub value: String,
    pub evidence_hash: String,
    pub confirmed: bool,
    #[serde(default)]
    pub dismissed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FindingDismissal {
    id: String,
    reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Ioc,
    Hypothesis,
    Technique,
    Impact,
    Recommendation,
}

impl FindingKind {
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "ioc" => Ok(Self::Ioc),
            "hypothesis" => Ok(Self::Hypothesis),
            "technique" => Ok(Self::Technique),
            "impact" => Ok(Self::Impact),
            "recommendation" => Ok(Self::Recommendation),
            _ => Err(AppError::Policy("invalid finding type".into())),
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::Ioc => "IOCs",
            Self::Hypothesis => "Hypotheses",
            Self::Technique => "ATT&CK techniques",
            Self::Impact => "Impact",
            Self::Recommendation => "Recommendations",
        }
    }
}

impl Engine<'_> {
    pub fn add_finding(
        &self,
        id: &CaseId,
        kind: FindingKind,
        value: &str,
        evidence_hash: &str,
    ) -> Result<String, AppError> {
        self.require_attended_analyst("add case finding")?;
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        self.propose_finding_unlocked(id, kind, value, evidence_hash, "analyst")
    }

    pub(crate) fn propose_finding_unlocked(
        &self,
        id: &CaseId,
        kind: FindingKind,
        value: &str,
        evidence_hash: &str,
        origin: &str,
    ) -> Result<String, AppError> {
        if value.trim().is_empty() || value.len() > 2_000 || value.contains('\0') {
            return Err(AppError::Policy("invalid finding value".into()));
        }
        if !self
            .evidence_store
            .evidence_hashes(id)?
            .iter()
            .any(|hash| hash == evidence_hash)
        {
            return Err(AppError::Policy(
                "finding evidence is absent from case".into(),
            ));
        }
        let finding = Finding {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            value: value.to_owned(),
            evidence_hash: evidence_hash.to_owned(),
            confirmed: false,
            dismissed: false,
        };
        self.audit(
            id,
            origin,
            "FindingProposed",
            &serde_json::to_string(&finding).map_err(|e| AppError::Storage(e.to_string()))?,
            Some(evidence_hash),
        )?;
        Ok(finding.id)
    }

    pub fn confirm_finding(&self, id: &CaseId, finding_id: &str) -> Result<(), AppError> {
        self.require_attended_analyst("confirm case finding")?;
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        let findings = self.findings_unlocked(id, &self.audit_log.entries(id)?)?;
        if !findings
            .iter()
            .any(|finding| finding.id == finding_id && !finding.confirmed && !finding.dismissed)
        {
            return Err(AppError::Policy("unconfirmed finding not found".into()));
        }
        self.audit(id, "analyst", "FindingConfirmed", finding_id, None)
    }

    pub fn dismiss_finding(
        &self,
        id: &CaseId,
        finding_id: &str,
        reason: &str,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("dismiss case finding")?;
        if reason.trim().is_empty() || reason.len() > 500 {
            return Err(AppError::Policy("invalid dismissal reason".into()));
        }
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        let findings = self.findings_unlocked(id, &self.audit_log.entries(id)?)?;
        if !findings
            .iter()
            .any(|finding| finding.id == finding_id && !finding.confirmed && !finding.dismissed)
        {
            return Err(AppError::Policy("open finding not found".into()));
        }
        let event = FindingDismissal {
            id: finding_id.to_owned(),
            reason: reason.to_owned(),
        };
        self.audit(
            id,
            "analyst",
            "FindingDismissed",
            &serde_json::to_string(&event).map_err(|error| AppError::Storage(error.to_string()))?,
            None,
        )
    }

    pub fn findings(&self, id: &CaseId) -> Result<Vec<Finding>, AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        self.findings_unlocked(id, &self.audit_log.entries(id)?)
    }

    pub(crate) fn findings_unlocked(
        &self,
        id: &CaseId,
        entries: &[SignedEntry],
    ) -> Result<Vec<Finding>, AppError> {
        let known_evidence = self.evidence_store.evidence_hashes(id)?;
        let mut findings = BTreeMap::<String, Finding>::new();
        for entry in entries {
            match entry.kind.as_str() {
                "FindingProposed" => {
                    let finding: Finding = serde_json::from_str(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    if !matches!(entry.origin.as_str(), "analyst" | "model")
                        || (entry.origin == "analyst" && entry.actor != Actor::Analyst)
                        || finding.confirmed
                        || finding.dismissed
                        || uuid::Uuid::parse_str(&finding.id).is_err()
                        || finding.value.trim().is_empty()
                        || finding.value.len() > 2_000
                        || finding.value.contains('\0')
                        || entry.evidence.as_deref() != Some(finding.evidence_hash.as_str())
                        || !known_evidence.contains(&finding.evidence_hash)
                        || findings.insert(finding.id.clone(), finding).is_some()
                    {
                        return Err(AppError::InvalidChain(entry.seq));
                    }
                }
                "FindingConfirmed" => {
                    let finding = findings
                        .get_mut(&entry.payload)
                        .ok_or(AppError::InvalidChain(entry.seq))?;
                    if entry.actor != Actor::Analyst
                        || finding.confirmed
                        || finding.dismissed
                        || entry.evidence.is_some()
                    {
                        return Err(AppError::InvalidChain(entry.seq));
                    }
                    finding.confirmed = true;
                }
                "FindingDismissed" => {
                    let event: FindingDismissal = serde_json::from_str(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    let finding = findings
                        .get_mut(&event.id)
                        .ok_or(AppError::InvalidChain(entry.seq))?;
                    if entry.actor != Actor::Analyst
                        || finding.confirmed
                        || finding.dismissed
                        || entry.evidence.is_some()
                        || event.reason.trim().is_empty()
                        || event.reason.len() > 500
                    {
                        return Err(AppError::InvalidChain(entry.seq));
                    }
                    finding.dismissed = true;
                }
                _ => {}
            }
        }
        Ok(findings.into_values().collect())
    }

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
        for event in self.graph.timeline(id, 100)? {
            let _ = writeln!(
                report,
                "- {} — {} [evidence: {}#{}]",
                safe_markdown(&event.at),
                safe_markdown(&event.event),
                event.evidence_hash,
                event.record_index
            );
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
                .filter(|finding| finding.confirmed && finding.kind.heading() == kind.heading())
            {
                let _ = writeln!(
                    report,
                    "- {} [evidence: {}]",
                    safe_markdown(&finding.value),
                    finding.evidence_hash
                );
            }
        }
        Ok(report)
    }
}
